// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// A journeys run needs a real PostgreSQL 16. Two backends exist: a container from a LOCAL image (docker; the
// default) and an unprivileged server started from a PostgreSQL installation directory (`--pg-local DIR`, a
// directory holding bin/{initdb,pg_ctl,postgres} and lib/), for a host without a container runtime. Both are
// real servers reached over loopback TCP by the same psycopg-based applications; only the administration
// (create the database, apply the schema, read the statement log) differs.

// pgQueryScript runs one statement through psycopg (the reference estate's own driver; psql is not part of
// every PostgreSQL installation) and prints rows like `psql -At`: values joined by `|`, one row per line.
const pgQueryScript = `import os, sys, psycopg
with psycopg.connect(os.environ["PGDSN"], autocommit=True) as conn:
    cur = conn.execute(sys.argv[1])
    if cur.description:
        for row in cur:
            print("|".join("" if v is None else str(v) for v in row))
`

// pgScriptFile executes a whole SQL file (several statements) and stops at the first error.
const pgScriptFile = `import os, sys, psycopg
with psycopg.connect(os.environ["PGDSN"], autocommit=True) as conn:
    conn.execute(open(sys.argv[1], encoding="utf-8").read())
`

func (j *journeyRun) localPG() bool { return j.pgLocal != "" }

func (j *journeyRun) pgEnv() []string {
	return []string{"LD_LIBRARY_PATH=" + filepath.Join(j.pgLocal, "lib")}
}

// pythonEnv is the environment of the reference estate's Python processes.
func (j *journeyRun) pythonEnv(dsn string) []string {
	return []string{"PYTHONPATH=" + j.pyPath, "PYTHONDONTWRITEBYTECODE=1", "PGDSN=" + dsn}
}

func (j *journeyRun) startLocalPostgres() error {
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	j.pgPass = hex.EncodeToString(rnd[:])
	j.pgDir = filepath.Join(j.work, "pgdata")
	j.pgLog = filepath.Join(j.work, "postgres.log")
	sock := filepath.Join(j.work, "pgsock")
	if err := os.MkdirAll(sock, 0o700); err != nil {
		return err
	}
	pwfile := filepath.Join(j.work, "pgpass")
	if err := os.WriteFile(pwfile, []byte(j.pgPass+"\n"), 0o600); err != nil {
		return err
	}
	bin := filepath.Join(j.pgLocal, "bin")
	if _, err := runOut(j.root, j.pgEnv(), filepath.Join(bin, "initdb"), "-D", j.pgDir, "-U", "postgres", "--pwfile="+pwfile, "-A", "scram-sha-256", "-E", "UTF8"); err != nil {
		return fmt.Errorf("initdb: %w", err)
	}
	addr, err := freeAddress()
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	j.pgPort = port
	// log_statement=all lets the smoke prove the SQL text (with its canary literal) really reached PostgreSQL; the
	// statement log is PostgreSQL's own and never stored by the product.
	opts := "-p " + port + " -k " + sock + " -c listen_addresses=127.0.0.1 -c log_statement=all"
	if _, err = runOut(j.root, j.pgEnv(), filepath.Join(bin, "pg_ctl"), "-D", j.pgDir, "-o", opts, "-l", j.pgLog, "-w", "start"); err != nil {
		return fmt.Errorf("pg_ctl start: %w", err)
	}
	for i := 0; ; i++ {
		if _, err = j.pgRun("postgres", "select 1"); err == nil {
			break
		}
		if i > 100 {
			return errors.New("postgres did not become ready")
		}
		time.Sleep(300 * time.Millisecond)
	}
	if _, err = j.pgRun("postgres", "create database reference"); err != nil {
		return err
	}
	return nil
}

// pgRun runs one statement against the named database of the local server.
func (j *journeyRun) pgRun(database, query string) (string, error) {
	dsn := "postgresql://postgres:" + j.pgPass + "@127.0.0.1:" + j.pgPort + "/" + database
	return runOut(j.root, j.pythonEnv(dsn), j.python, "-c", pgQueryScript, query)
}

func (j *journeyRun) applyLocalSchema(schemaPath string) error {
	dsn := "postgresql://postgres:" + j.pgPass + "@127.0.0.1:" + j.pgPort + "/reference"
	if _, err := runOut(j.root, j.pythonEnv(dsn), j.python, "-c", pgScriptFile, schemaPath); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	return nil
}

// postgresStatementLog is the server's own statement log (docker logs, or the local server's log file).
func (j *journeyRun) postgresStatementLog() (string, error) {
	if j.localPG() {
		raw, err := os.ReadFile(j.pgLog)
		return string(raw), err
	}
	out, err := exec.Command("docker", "logs", j.pgName).CombinedOutput()
	return string(out), err
}

// stopPostgres removes the database server of the run; errors are not reported (best effort at teardown).
func (j *journeyRun) stopPostgres() {
	if j.localPG() {
		if j.pgDir != "" {
			_, _ = runOut(j.root, j.pgEnv(), filepath.Join(j.pgLocal, "bin", "pg_ctl"), "-D", j.pgDir, "-m", "immediate", "-w", "stop")
		}
		return
	}
	if j.pgName != "" {
		_ = exec.Command("docker", "rm", "-f", "-v", j.pgName).Run()
	}
}

// postgresVersion records the server binary version of a local installation.
func (j *journeyRun) localPostgresBinaryVersion() (string, error) {
	out, err := runOut(j.root, j.pgEnv(), filepath.Join(j.pgLocal, "bin", "postgres"), "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}
