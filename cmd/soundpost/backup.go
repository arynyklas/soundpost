// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/backup"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

const backupUsage = `usage: soundpost backup <command> [flags]

  keygen            --key-dir DIR --id ID                      create a backup key-encryption key file (0600)
  authority-keygen  --out FILE --id ID [--restricted-out FILE] create the restore authority's signing/sealing keys
  authority-init    (--data-dir DIR | --installation ID) --authority-keys FILE <authority destination>
  create            --data-dir DIR --admin-email EMAIL --key-dir DIR --data-kek ID --secret-kek ID
                    --authority-keys FILE <backup destination> <authority destination>
  list              <backup destination>
  restore           --backup-id ID --root DIR --key-dir DIR --authority-keys FILE <backup destination> <authority destination>
  activate          --root DIR --authority-keys FILE <authority destination>

A destination is --<name>-dir DIR, or --<name>-s3-endpoint URL --<name>-s3-region R --<name>-s3-bucket B
[--<name>-s3-prefix P]; S3 credentials come from the environment variables
SOUNDPOST_<NAME>_S3_ACCESS_KEY and SOUNDPOST_<NAME>_S3_SECRET_KEY, never from flags.
<backup destination> uses the name "dest", <authority destination> the name "authority".
The administrator password for create is read from SOUNDPOST_ADMIN_PASSWORD (and the
optional one-time code from SOUNDPOST_ADMIN_CODE). create, authority-init (with --data-dir)
and activate open the installation exclusively: stop the server first.`

// cliError is an operator-facing message written by this file: static text that
// carries no runtime data (no path, key, input value or error text), so it is
// printed as it is.
type cliError string

func (e cliError) Error() string { return string(e) }

const (
	errUsage           = cliError(backupUsage)
	errBadFlags        = cliError("invalid or unknown flag\n\n" + backupUsage)
	errNoAuthorityKeys = cliError("--authority-keys is required")
	// errUnsupportedMode is the typed refusal for a distributed node's directory: backup,
	// restore and activation implement the single-node layout only.
	errUnsupportedMode = cliError("unsupported_mode: backup, restore and activate support single-node installations only (--mode single); a distributed node's data directory cannot be backed up or restored (see docs/operations/backup-restore.md)")
)

// parseFlags parses a subcommand's flags. A flag error echoes the operator's own
// input, so it is replaced by the static usage message.
func parseFlags(f *flag.FlagSet, args []string) error {
	if f.Parse(args) != nil {
		return errBadFlags
	}
	return nil
}

// backupFailureLine is what main prints for a failed `backup` command: the typed
// public error code (and the fault's approved detail, when it has one), which is
// what the failure matrix in docs/operations/backup-restore.md is keyed by. The
// text of any other error is withheld: it can name paths, and no error from this
// tree may carry a key or a secret.
func backupFailureLine(err error) string {
	var message cliError
	if errors.As(err, &message) {
		if message == errUsage {
			return string(message)
		}
		return "soundpost backup: " + string(message)
	}
	var fault *model.Fault
	if errors.As(err, &fault) {
		line := "soundpost backup failed: " + string(fault.Code)
		if detail := safeDetail(fault); detail != "" {
			line += " (" + detail + ")"
		}
		if fault.Retryable {
			line += " [retryable]"
		}
		return line
	}
	return "soundpost backup failed: internal error (details withheld; the underlying error can name paths)"
}

// safeDetail is a fault's approved detail when it is a short token and adds
// something to the code.
func safeDetail(f *model.Fault) string {
	d := f.SafeDetail
	if d == "" || d == string(f.Code) || len(d) > 80 {
		return ""
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == ':' || r == '.' || r == '-') {
			return ""
		}
	}
	return d
}
func runBackup(args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "keygen":
		return backupKeygen(args[1:])
	case "authority-keygen":
		return backupAuthorityKeygen(args[1:])
	case "authority-init":
		return backupAuthorityInit(args[1:])
	case "create":
		return backupCreate(args[1:])
	case "list":
		return backupList(args[1:])
	case "restore":
		return backupRestore(args[1:])
	case "activate":
		return backupActivate(args[1:])
	}
	return errUsage
}

// requireSingleNode refuses a distributed node's data directory with errUnsupportedMode
// before anything opens it (opening one as a single node fails inside the replica journal
// with an untyped error).
func requireSingleNode(dir string) error {
	distributed, err := backup.IsDistributedDirectory(dir)
	if err != nil {
		return err
	}
	if distributed {
		return errUnsupportedMode
	}
	return nil
}

// destinationFlags registers --<name>-dir and the --<name>-s3-* flags.
type destinationFlags struct {
	name                                  string
	dir, endpoint, region, bucket, prefix *string
}

func newDestinationFlags(f *flag.FlagSet, name string) *destinationFlags {
	return &destinationFlags{
		name:     name,
		dir:      f.String(name+"-dir", "", "local destination directory"),
		endpoint: f.String(name+"-s3-endpoint", "", "S3-compatible HTTPS endpoint"),
		region:   f.String(name+"-s3-region", "", "S3 region"),
		bucket:   f.String(name+"-s3-bucket", "", "S3 bucket"),
		prefix:   f.String(name+"-s3-prefix", "", "S3 key prefix"),
	}
}

func (d *destinationFlags) open() (backup.Destination, error) {
	switch {
	case *d.dir != "" && *d.endpoint != "":
		return nil, cliError(fmt.Sprintf("--%s-dir and --%s-s3-endpoint are exclusive", d.name, d.name))
	case *d.dir != "":
		return backup.NewLocalDestination(*d.dir)
	case *d.endpoint != "":
		env := "SOUNDPOST_" + strings.ToUpper(d.name) + "_S3_"
		return backup.NewS3Destination(backup.S3Config{Endpoint: *d.endpoint, Region: *d.region, Bucket: *d.bucket, Prefix: *d.prefix, AccessKey: os.Getenv(env + "ACCESS_KEY"), SecretKey: os.Getenv(env + "SECRET_KEY")})
	}
	return nil, cliError(fmt.Sprintf("--%s-dir or --%s-s3-endpoint is required", d.name, d.name))
}

func flagSet(name string) *flag.FlagSet {
	f := flag.NewFlagSet("backup "+name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}

func printJSON(v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(raw))
	return err
}

func backupKeygen(args []string) error {
	f := flagSet("keygen")
	dir := f.String("key-dir", "", "")
	id := f.String("id", "", "")
	if err := parseFlags(f, args); err != nil {
		return err
	}
	if *dir == "" || *id == "" {
		return errUsage
	}
	key, err := backup.GenerateKey(*id)
	if err != nil {
		return err
	}
	if err = backup.WriteKeyFile(*dir, key); err != nil {
		return err
	}
	fmt.Println("wrote key", key.ID())
	return nil
}

func backupAuthorityKeygen(args []string) error {
	f := flagSet("authority-keygen")
	out := f.String("out", "", "")
	restricted := f.String("restricted-out", "", "")
	id := f.String("id", "", "")
	if err := parseFlags(f, args); err != nil {
		return err
	}
	if *out == "" || *id == "" {
		return errUsage
	}
	keys, err := backup.GenerateAuthorityKeys(*id)
	if err != nil {
		return err
	}
	if err = backup.WriteAuthorityKeys(*out, keys); err != nil {
		return err
	}
	if *restricted != "" {
		if err = backup.WriteAuthorityKeys(*restricted, keys.Restricted()); err != nil {
			return err
		}
	}
	fmt.Println("wrote authority keys", keys.ID)
	return nil
}

func openAuthority(dest *destinationFlags, keysPath string) (*backup.Authority, error) {
	if keysPath == "" {
		return nil, errNoAuthorityKeys
	}
	keys, err := backup.ReadAuthorityKeys(keysPath)
	if err != nil {
		return nil, err
	}
	d, err := dest.open()
	if err != nil {
		return nil, err
	}
	return backup.NewAuthority(d, keys, time.Now)
}

func backupAuthorityInit(args []string) error {
	f := flagSet("authority-init")
	dataDir := f.String("data-dir", "", "")
	installation := f.String("installation", "", "")
	keysPath := f.String("authority-keys", "", "")
	dest := newDestinationFlags(f, "authority")
	if err := parseFlags(f, args); err != nil {
		return err
	}
	var id model.ID
	switch {
	case *installation != "":
		parsed, err := model.ParseID(*installation)
		if err != nil {
			return err
		}
		id = parsed
	case *dataDir != "":
		if err := requireSingleNode(*dataDir); err != nil {
			return err
		}
		store, err := control.Open(*dataDir)
		if err != nil {
			return err
		}
		err = store.View(context.Background(), func(st control.State) error { id = st.Installation; return nil })
		store.Close()
		if err != nil {
			return err
		}
	default:
		return errUsage
	}
	authority, err := openAuthority(dest, *keysPath)
	if err != nil {
		return err
	}
	authorityID, err := authority.Initialize(context.Background(), id)
	if err != nil {
		return err
	}
	fmt.Println("authority", authorityID.String(), "bound to installation", id.String())
	return nil
}

func backupCreate(args []string) error {
	f := flagSet("create")
	dataDir := f.String("data-dir", "", "")
	email := f.String("admin-email", "", "")
	reason := f.String("reason", "scheduled backup", "")
	keyDir := f.String("key-dir", "", "")
	dataKEK := f.String("data-kek", "", "")
	secretKEK := f.String("secret-kek", "", "")
	attempts := f.String("attempts-dir", "", "")
	keysPath := f.String("authority-keys", "", "")
	dest := newDestinationFlags(f, "dest")
	authorityDest := newDestinationFlags(f, "authority")
	if err := parseFlags(f, args); err != nil {
		return err
	}
	if *dataDir == "" || *email == "" || *keyDir == "" || *dataKEK == "" || *secretKEK == "" {
		return errUsage
	}
	if err := requireSingleNode(*dataDir); err != nil {
		return err
	}
	if *attempts == "" {
		*attempts = filepath.Join(*dataDir, "backup-attempts")
	}
	destination, err := dest.open()
	if err != nil {
		return err
	}
	authority, err := openAuthority(authorityDest, *keysPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	app, err := appcore.Open(*dataDir)
	if err != nil {
		return err
	}
	defer app.Close()
	plane := backup.EngineDataPlane(app.Storage)
	svc, err := backup.New(backup.Config{Control: app.Control, Data: plane, Processed: backup.AppliedProcessed(plane), Authority: authority, Authorizer: app.Auth, Keys: backup.KeyDir(*keyDir), DataKEK: *dataKEK, SecretKEK: *secretKEK, Attempts: backup.DirAttempts(*attempts), Clock: time.Now})
	if err != nil {
		return err
	}
	if report, err := svc.Reap(ctx); err != nil {
		return err
	} else if report.Unowned != 0 {
		fmt.Fprintln(os.Stderr, "warning: journal pins with no incomplete backup attempt were left alone:", report.Unowned)
	}
	session, err := app.Auth.Login(ctx, *email, os.Getenv("SOUNDPOST_ADMIN_PASSWORD"), os.Getenv("SOUNDPOST_ADMIN_CODE"))
	if err != nil {
		return err
	}
	credential, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		return err
	}
	defer app.Auth.Logout(ctx, session.Token)
	scope, err := app.Auth.InstanceScope(ctx, credential, *reason)
	if err != nil {
		return err
	}
	started := time.Now()
	manifest, err := svc.Run(ctx, scope, destination)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"backup_id": manifest.ID.String(), "created_at_ns": manifest.CreatedAt, "completed_at_ns": manifest.CompletedAt, "expires_at_ns": manifest.ExpiresAt, "duration_ms": time.Since(started).Milliseconds(), "objects": len(manifest.Objects), "control_revision": manifest.Control.Revision, "authority_sequence": manifest.Deletion.Sequence, "authority_generation": manifest.Deletion.Generation, "gaps": len(manifest.Gaps)})
}

func backupList(args []string) error {
	f := flagSet("list")
	dest := newDestinationFlags(f, "dest")
	if err := parseFlags(f, args); err != nil {
		return err
	}
	destination, err := dest.open()
	if err != nil {
		return err
	}
	names, err := destination.List(context.Background(), "backups/")
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.HasSuffix(name, "/manifest.json") {
			fmt.Println(strings.TrimSuffix(strings.TrimPrefix(name, "backups/"), "/manifest.json"))
		}
	}
	return nil
}

func backupRestore(args []string) error {
	f := flagSet("restore")
	backupID := f.String("backup-id", "", "")
	root := f.String("root", "", "")
	keyDir := f.String("key-dir", "", "")
	keysPath := f.String("authority-keys", "", "")
	dest := newDestinationFlags(f, "dest")
	authorityDest := newDestinationFlags(f, "authority")
	if err := parseFlags(f, args); err != nil {
		return err
	}
	id, err := model.ParseID(*backupID)
	if err != nil || *root == "" || *keyDir == "" {
		return errUsage
	}
	if err = requireSingleNode(*root); err != nil {
		return err
	}
	source, err := dest.open()
	if err != nil {
		return err
	}
	authority, err := openAuthority(authorityDest, *keysPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	keys := backup.KeyDir(*keyDir)
	manifest, err := backup.LoadManifest(ctx, source, id, keys)
	if err != nil {
		return err
	}
	restorer, err := backup.NewRestorer(backup.RestoreConfig{Keys: keys, Source: source, Clock: time.Now})
	if err != nil {
		return err
	}
	started := time.Now()
	report, err := restorer.Restore(ctx, manifest, backup.DestinationRoot(*root), authority)
	if err != nil {
		return err
	}
	if err = printJSON(map[string]any{"backup_id": report.BackupID.String(), "control_revision": report.ControlRevision, "authority_sequence": report.AuthoritySequence, "authority_generation": report.AuthorityGeneration, "tombstones": report.Tombstones, "objects": report.Objects, "gaps_verified": report.GapsVerified, "quota_certificate": report.QuotaCertificate.String(), "quarantined": report.Quarantined, "duration_ms": time.Since(started).Milliseconds()}); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "The restored installation admits nothing and serves nothing until `soundpost backup activate` succeeds.")
	fmt.Fprintln(os.Stderr, "A one-time recovery bootstrap token was written to the root's bootstrap.token file (mode 0600); it is not printed.")
	return nil
}

func backupActivate(args []string) error {
	f := flagSet("activate")
	root := f.String("root", "", "")
	keysPath := f.String("authority-keys", "", "")
	authorityDest := newDestinationFlags(f, "authority")
	if err := parseFlags(f, args); err != nil {
		return err
	}
	if *root == "" {
		return errUsage
	}
	if err := requireSingleNode(*root); err != nil {
		return err
	}
	authority, err := openAuthority(authorityDest, *keysPath)
	if err != nil {
		return err
	}
	// A restored root holds its engine closed until this command lifts the restore hold,
	// so the artifact-reference validation Open runs is deferred to the activation itself
	// (appcore.App.RestoreReady runs it right after the hold is lifted).
	app, err := appcore.OpenForActivation(*root)
	if err != nil {
		return err
	}
	defer app.Close()
	if err = app.Retention.UseAuthority(authority); err != nil {
		return err
	}
	report, err := backup.Activate(context.Background(), backup.DestinationRoot(*root), app, authority, time.Now)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"authority_generation": report.AuthorityGeneration, "tombstones": report.Tombstones, "ready": true})
}
