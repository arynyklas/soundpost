//! `cargo xtask toolchain verify`: the installed Rust toolchain is the pinned one, from the archives the support
//! document records.
//!
//! Lab VMs have no rustup and no internet. A toolchain there is installed from the standalone archives listed in
//! `docs/support/rust-toolchain.md`, and the install step writes `lib/rustlib/soundpost-receipt.sha256` into the
//! installed prefix (sha256sum format, one line per archive installed). `verify` therefore checks two things: the
//! compiler reports the pinned version, and the installation it belongs to was made from archives whose sha256 the
//! document records.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const RECEIPT: &str = "soundpost-receipt.sha256";

/// One `<sha256>  <archive>.tar.xz` line, in the document or in an installation receipt.
#[derive(Debug, PartialEq, Eq)]
pub struct Archive {
    pub sha256: String,
    pub name: String,
}

/// Every archive line (`sha256sum` format) in `text`; other lines are ignored.
pub fn archives(text: &str) -> Vec<Archive> {
    text.lines()
        .filter_map(|line| {
            let (sha256, name) = line.trim().split_once("  ")?;
            let hex = sha256.len() == 64
                && sha256
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            let archive = name.ends_with(".tar.xz") && !name.contains(char::is_whitespace);
            (hex && archive).then(|| Archive {
                sha256: sha256.to_owned(),
                name: name.to_owned(),
            })
        })
        .collect()
}

fn toml_value<'a>(toml: &'a str, key: &str) -> Option<&'a str> {
    toml.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == key).then(|| v.trim())
    })
}

/// `channel` of `rust-toolchain.toml`; it must be an exact version, not a channel name.
pub fn pinned_channel(toml: &str) -> Result<String, String> {
    let value = toml_value(toml, "channel").ok_or("rust-toolchain.toml has no channel")?;
    let channel = value.trim_matches('"');
    let exact = !channel.is_empty()
        && channel.split('.').count() == 3
        && channel.split('.').all(|p| p.parse::<u32>().is_ok());
    if exact {
        Ok(channel.to_owned())
    } else {
        Err(format!(
            "rust-toolchain.toml channel {value} is not an exact x.y.z version"
        ))
    }
}

/// `targets` of `rust-toolchain.toml` (a single-line array).
pub fn pinned_targets(toml: &str) -> Result<Vec<String>, String> {
    let value = toml_value(toml, "targets").ok_or("rust-toolchain.toml has no targets")?;
    let inner = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .ok_or("rust-toolchain.toml targets is not a one-line array")?;
    Ok(inner
        .split(',')
        .map(|t| t.trim().trim_matches('"').to_owned())
        .filter(|t| !t.is_empty())
        .collect())
}

fn output(rustc: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(rustc)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", rustc.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} {} failed: {}",
            rustc.display(),
            args.join(" "),
            out.status
        ));
    }
    String::from_utf8(out.stdout)
        .map_err(|_| format!("{} {} printed non-UTF-8", rustc.display(), args.join(" ")))
}

/// The version `rustc --version` reports, e.g. `1.100.1` for `rustc 1.100.1 (20ddd0171 2026-11-25)`.
pub fn rustc_version(rustc: &Path) -> Result<String, String> {
    let text = output(rustc, &["--version"])?;
    text.split_whitespace()
        .nth(1)
        .map(str::to_owned)
        .ok_or_else(|| format!("unexpected `rustc --version` output: {}", text.trim()))
}

/// Fails unless `rustc` reports exactly `pinned`.
pub fn verify(rustc: &Path, pinned: &str) -> Result<(), String> {
    let got = rustc_version(rustc)?;
    if got == pinned {
        Ok(())
    } else {
        Err(format!(
            "{} reports rustc {got}, rust-toolchain.toml pins {pinned}",
            rustc.display()
        ))
    }
}

fn sha_of<'a>(list: &'a [Archive], name: &str, what: &str) -> Result<Option<&'a str>, String> {
    let mut shas = list
        .iter()
        .filter(|a| a.name == name)
        .map(|a| a.sha256.as_str());
    let first = shas.next();
    match shas.find(|s| Some(*s) != first) {
        Some(other) => Err(format!(
            "{what} records two different sha256 for {name}: {} and {other}",
            first.unwrap_or_default()
        )),
        None => Ok(first),
    }
}

/// Fails unless the installation `rustc` belongs to was made from the archives `doc` records: the receipt in the
/// installed prefix must list the host toolchain archive and the std archive of every Linux target in `targets`,
/// each with the sha256 the document gives, and the installer's manifests for them must be present.
/// Archives of other targets (the Windows std) are recorded in the document but not installed on Linux labs.
pub fn verify_install(
    rustc: &Path,
    pinned: &str,
    targets: &[String],
    doc: &str,
) -> Result<(), String> {
    let sysroot = PathBuf::from(output(rustc, &["--print", "sysroot"])?.trim());
    let host = output(rustc, &["-vV"])?
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_owned))
        .ok_or("`rustc -vV` has no host line")?;
    let rustlib = sysroot.join("lib").join("rustlib");
    let receipt_path = rustlib.join(RECEIPT);
    let receipt_text = fs::read_to_string(&receipt_path).map_err(|e| {
        format!(
            "no installation receipt {} ({e}); reinstall from the archives in docs/support/rust-toolchain.md",
            receipt_path.display()
        )
    })?;
    let receipt = archives(&receipt_text);
    let recorded = archives(doc);

    for entry in &receipt {
        match sha_of(&recorded, &entry.name, "docs/support/rust-toolchain.md")? {
            Some(sha) if sha == entry.sha256 => {}
            Some(sha) => {
                return Err(format!(
                    "installed {} has sha256 {} in the receipt, the document records {sha}",
                    entry.name, entry.sha256
                ));
            }
            None => {
                return Err(format!(
                    "installed archive {} is not recorded in docs/support/rust-toolchain.md",
                    entry.name
                ));
            }
        }
    }

    let mut required = vec![(
        format!("rust-{pinned}-{host}.tar.xz"),
        "manifest-rustc".to_owned(),
    )];
    for target in targets.iter().filter(|t| t.contains("-linux-")) {
        required.push((
            format!("rust-std-{pinned}-{target}.tar.xz"),
            format!("manifest-rust-std-{target}"),
        ));
    }
    for (name, manifest) in required {
        if sha_of(&recorded, &name, "docs/support/rust-toolchain.md")?.is_none() {
            return Err(format!(
                "docs/support/rust-toolchain.md records no sha256 for {name}"
            ));
        }
        if sha_of(&receipt, &name, "the receipt")?.is_none() {
            return Err(format!(
                "the installation receipt {} does not list {name}",
                receipt_path.display()
            ));
        }
        if !rustlib.join(&manifest).is_file() {
            return Err(format!(
                "{name} is in the receipt but {} is missing: the installation is incomplete",
                rustlib.join(&manifest).display()
            ));
        }
    }
    Ok(())
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// `cargo xtask toolchain <args>`; returns the line to print on success.
pub fn run(args: &[String]) -> Result<String, String> {
    match args {
        [cmd] if cmd == "verify" => {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
            let toml = read(&root.join("rust-toolchain.toml"))?;
            let doc = read(&root.join("docs").join("support").join("rust-toolchain.md"))?;
            let pinned = pinned_channel(&toml)?;
            let targets = pinned_targets(&toml)?;
            let rustc = PathBuf::from(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()));
            verify(&rustc, &pinned)?;
            verify_install(&rustc, &pinned, &targets, &doc)?;
            Ok(format!("ok {pinned}"))
        }
        _ => Err("usage: cargo xtask toolchain verify".to_owned()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    // A freshly written script must not be exec'd while another test thread is forking with its write fd open.
    static SERIAL: Mutex<()> = Mutex::new(());

    const HOST: &str = "x86_64-unknown-linux-gnu";
    const SHA_HOST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SHA_MUSL: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const SHA_WIN: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const OTHER: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    struct Fixture {
        dir: PathBuf,
        rustc: PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Fixture {
        /// A fake `rustc` reporting `version`, whose sysroot holds the manifests and receipt of a healthy install.
        fn new(name: &str, version: &str) -> Fixture {
            let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            let dir =
                std::env::temp_dir().join(format!("xtask-toolchain-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let sysroot = dir.join("sysroot");
            let rustlib = sysroot.join("lib").join("rustlib");
            fs::create_dir_all(&rustlib).expect("create sysroot");
            for manifest in [
                "manifest-rustc",
                "manifest-rust-std-x86_64-unknown-linux-musl",
            ] {
                fs::write(rustlib.join(manifest), "").expect("write manifest");
            }
            let receipt = format!(
                "{SHA_HOST}  rust-1.100.1-{HOST}.tar.xz\n{SHA_MUSL}  rust-std-1.100.1-x86_64-unknown-linux-musl.tar.xz\n"
            );
            fs::write(rustlib.join(RECEIPT), receipt).expect("write receipt");
            let script = format!(
                "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'rustc {version} (0123abcde 2026-01-01)';;\n  -vV) printf 'rustc {version} (0123abcde 2026-01-01)\\nbinary: rustc\\nhost: {HOST}\\nrelease: {version}\\n';;\n  --print) echo '{}';;\nesac\n",
                sysroot.display()
            );
            let rustc = dir.join("rustc");
            fs::write(&rustc, script).expect("write fake rustc");
            fs::set_permissions(&rustc, fs::Permissions::from_mode(0o755))
                .expect("chmod fake rustc");
            Fixture {
                dir,
                rustc,
                _guard: guard,
            }
        }

        fn rustlib(&self) -> PathBuf {
            self.dir.join("sysroot").join("lib").join("rustlib")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn doc() -> String {
        format!(
            "# doc\n\n```\n{SHA_HOST}  rust-1.100.1-{HOST}.tar.xz\n{SHA_MUSL}  rust-std-1.100.1-x86_64-unknown-linux-musl.tar.xz\n{SHA_WIN}  rust-std-1.100.1-x86_64-pc-windows-msvc.tar.xz\n```\n"
        )
    }

    fn targets() -> Vec<String> {
        vec![
            "x86_64-unknown-linux-musl".to_owned(),
            "x86_64-pc-windows-msvc".to_owned(),
        ]
    }

    #[test]
    fn refuses_a_different_rustc() {
        let fx = Fixture::new("different", "1.99.0");
        let err = verify(&fx.rustc, "1.100.1").expect_err("a different rustc must be refused");
        assert!(
            err.contains("1.99.0") && err.contains("1.100.1"),
            "error must name both versions: {err}"
        );
    }

    #[test]
    fn accepts_the_pinned_rustc() {
        let fx = Fixture::new("pinned", "1.100.1");
        verify(&fx.rustc, "1.100.1").expect("pinned version");
        verify_install(&fx.rustc, "1.100.1", &targets(), &doc()).expect("healthy install");
    }

    #[test]
    fn refuses_a_receipt_with_another_checksum() {
        let fx = Fixture::new("checksum", "1.100.1");
        let tampered = doc().replace(SHA_MUSL, OTHER);
        let err = verify_install(&fx.rustc, "1.100.1", &targets(), &tampered)
            .expect_err("checksum mismatch");
        assert!(
            err.contains(SHA_MUSL) && err.contains(OTHER),
            "error must name both checksums: {err}"
        );
    }

    #[test]
    fn refuses_a_missing_receipt() {
        let fx = Fixture::new("noreceipt", "1.100.1");
        fs::remove_file(fx.rustlib().join(RECEIPT)).expect("remove receipt");
        let err = verify_install(&fx.rustc, "1.100.1", &targets(), &doc()).expect_err("no receipt");
        assert!(err.contains("no installation receipt"), "{err}");
    }

    #[test]
    fn refuses_a_receipt_without_a_required_std() {
        let fx = Fixture::new("nostd", "1.100.1");
        fs::write(
            fx.rustlib().join(RECEIPT),
            format!("{SHA_HOST}  rust-1.100.1-{HOST}.tar.xz\n"),
        )
        .expect("write receipt");
        let err = verify_install(&fx.rustc, "1.100.1", &targets(), &doc())
            .expect_err("musl std not in receipt");
        assert!(
            err.contains("rust-std-1.100.1-x86_64-unknown-linux-musl.tar.xz"),
            "{err}"
        );
    }

    #[test]
    fn refuses_an_installation_missing_its_manifest() {
        let fx = Fixture::new("nomanifest", "1.100.1");
        fs::remove_file(
            fx.rustlib()
                .join("manifest-rust-std-x86_64-unknown-linux-musl"),
        )
        .expect("remove manifest");
        let err =
            verify_install(&fx.rustc, "1.100.1", &targets(), &doc()).expect_err("manifest missing");
        assert!(
            err.contains("manifest-rust-std-x86_64-unknown-linux-musl"),
            "{err}"
        );
    }

    #[test]
    fn refuses_an_archive_the_document_does_not_record() {
        let fx = Fixture::new("unrecorded", "1.100.1");
        let without_musl: String = doc()
            .lines()
            .filter(|l| !l.contains("linux-musl"))
            .map(|l| format!("{l}\n"))
            .collect();
        let err = verify_install(&fx.rustc, "1.100.1", &targets(), &without_musl)
            .expect_err("unrecorded archive");
        assert!(
            err.contains("not recorded")
                && err.contains("rust-std-1.100.1-x86_64-unknown-linux-musl.tar.xz"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    #[test]
    fn parses_channel_and_targets() {
        let toml = "[toolchain]\nchannel = \"1.2.3\"\ntargets = [\"a-b\", \"c-d\"]\n";
        assert_eq!(pinned_channel(toml), Ok("1.2.3".to_owned()));
        assert_eq!(
            pinned_targets(toml),
            Ok(vec!["a-b".to_owned(), "c-d".to_owned()])
        );
        assert!(
            pinned_channel("channel = \"stable\"").is_err(),
            "a moving channel is not a pin"
        );
    }

    #[test]
    fn archive_lines_need_a_full_sha256() {
        let sha = "a".repeat(64);
        let text = format!(
            "{sha}  rust-1.tar.xz\n{}  rust-2.tar.xz\n{sha}  notes.txt\n",
            "b".repeat(63)
        );
        assert_eq!(
            archives(&text),
            vec![Archive {
                sha256: sha,
                name: "rust-1.tar.xz".to_owned()
            }]
        );
    }

    #[test]
    fn the_document_records_every_archive_the_pin_needs() {
        let toml = read(&root().join("rust-toolchain.toml")).expect("rust-toolchain.toml");
        let doc = read(
            &root()
                .join("docs")
                .join("support")
                .join("rust-toolchain.md"),
        )
        .expect("rust-toolchain.md");
        let pinned = pinned_channel(&toml).expect("pinned channel");
        let recorded = archives(&doc);
        let mut needed = vec![format!("rust-{pinned}-x86_64-unknown-linux-gnu.tar.xz")];
        needed.extend(
            pinned_targets(&toml)
                .expect("targets")
                .iter()
                .map(|t| format!("rust-std-{pinned}-{t}.tar.xz")),
        );
        for name in needed {
            let sha = sha_of(&recorded, &name, "the document")
                .expect("consistent")
                .unwrap_or_else(|| panic!("document records no sha256 for {name}"));
            assert_eq!(sha.len(), 64);
        }
    }
}
