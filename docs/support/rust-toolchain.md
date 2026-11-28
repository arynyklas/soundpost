<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Rust toolchain: pin, offline install, lab-only tools

The Rust workspace builds with exactly one stable toolchain, named in [`rust-toolchain.toml`](../../rust-toolchain.toml). Lab VMs have no internet and no rustup, so the toolchain is installed from the standalone archives below and `cargo xtask toolchain verify` checks the result:

- `rustc --version` must report the version pinned in `rust-toolchain.toml` (an exact `x.y.z`, never a channel name);
- the installation must carry the receipt `lib/rustlib/soundpost-receipt.sha256` (written by the install step below), and every archive in it, plus the host archive and the std archive of each Linux target in `rust-toolchain.toml`, must have the sha256 recorded in the next section, with the installer's `manifest-*` files present.

It prints `ok <version>` and exits 0, or prints `error: ...` to stderr and exits 1. `RUSTC` overrides the `rustc` looked up on `PATH`.

## Stable 1.100.1 archives

`rustc 1.100.1 (20ddd0171 2026-11-25)`, LLVM 23.1.5, stable channel manifest dated 2026-11-27 (`https://static.rust-lang.org/dist/channel-rust-1.100.1.toml`). Each sha256 was computed on the downloaded file, matches the `.sha256` published next to it, and matches `xz_hash` in the channel manifest.

```
cf0d1dc00dbccc0bc63ec0bdb3da8bafe3e969cb3fbfa36dc5e6205467a50fea  rust-1.100.1-x86_64-unknown-linux-gnu.tar.xz
077a34ee391534782ff4b33e7d47f9517f694b92ae7c60e2a8526cce043da8ad  rust-std-1.100.1-x86_64-unknown-linux-musl.tar.xz
d0c5ef973943cc926f5d57716ffbaec82f94f30557da4607a668ba9b09b922a6  rust-std-1.100.1-x86_64-pc-windows-msvc.tar.xz
```

URL of each: `https://static.rust-lang.org/dist/<archive name>`. The Windows std archive is kept for the Windows build and is not installed on the Linux lab VMs (its target is named in `rust-toolchain.toml`; `verify` checks only the Linux targets' installation).

## Offline install (user level, under `/home/sp`)

1. On a VM with egress, download the three archives and their `.sha256` files into `~/dist/rust/1.100.1/`; compare with the table above (`sha256sum -c *.sha256`). Copy them to the other VMs by `scp` through a workstation.
2. On each VM, as the build user, with `V=1.100.1`, `H=x86_64-unknown-linux-gnu`, `M=x86_64-unknown-linux-musl`, `D=$HOME/dist/rust/$V`, `P=$HOME/.rust/$V`:

```
cd "$D" && sha256sum -c rust-$V-$H.tar.xz.sha256 rust-std-$V-$M.tar.xz.sha256
T=$(mktemp -d)
tar -xJf rust-$V-$H.tar.xz -C "$T" && "$T/rust-$V-$H/install.sh" --prefix="$P" --disable-ldconfig
tar -xJf rust-std-$V-$M.tar.xz -C "$T" && "$T/rust-std-$V-$M/install.sh" --prefix="$P" --disable-ldconfig
cat rust-$V-$H.tar.xz.sha256 rust-std-$V-$M.tar.xz.sha256 > "$P/lib/rustlib/soundpost-receipt.sha256"
rm -rf "$T"
```

3. Put `$P/bin` first on `PATH` (`PATH=$HOME/.rust/1.100.1/bin:$PATH`) and run `cargo xtask toolchain verify` in the repository: `ok 1.100.1`.

Nothing needs root, apt or a network. A new pin means new archives, new sha256 lines here, a new prefix and a new `rust-toolchain.toml`; the old prefix is deleted, not edited.

## Linker

`x86_64-unknown-linux-gnu` links through the `rust-lld` that ships in the 1.100.1 archive by default: `rustc --print link-args` shows `cc -B<prefix>/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld -fuse-ld=lld`, and a link error trace names `.../gcc-ld/ld.lld`. A hello-world build plus link at `opt-level=0` took 0.07 s on a lab VM (0.12 s with `-fuse-ld=bfd`). Debian's `mold` and `clang` packages therefore stay a dev/test-only option on `x86_64-unknown-linux-gnu`, are not installed on the lab VMs (no apt there), and are never used by `xtask release`, which builds the shipped binaries with the default linker of the pinned toolchain. Revisit only if a measured link of the real workspace is slow.

## Nightly for the ThreadSanitizer run (Task 1.9)

Used only for the ThreadSanitizer run (`-Zsanitizer=thread` with `-Zbuild-std`), never for a shipped binary. Dated nightly **2026-11-28** (`rustc 1.102.0-nightly (c82ce1563 2026-11-27)`), archives from `https://static.rust-lang.org/dist/2026-11-28/`; sha256 equals the `.sha256` published there and `xz_hash` in that day's `channel-rust-nightly.toml`. Downloaded, not installed; kept in `~/dist/rust/nightly-2026-11-28/` on a build VM, together with the channel manifest.

```
468a1f206e2c4e548b2fc7190769cbc1842cb3256221e5d1449e73353db642c9  rust-nightly-x86_64-unknown-linux-gnu.tar.xz
d496cbd3caa1bbab32f31fc28b464f16ca4cb66c0d1b53a9825a3ea6aa90d260  rust-src-nightly.tar.xz
```

Install with the same recipe into `$HOME/.rust/nightly-2026-11-28` (`rust-nightly-x86_64-unknown-linux-gnu` and `rust-src-nightly` directories; the second install adds `rust-src`). The nightly prefix is never put on `PATH` for ordinary builds; the sanitizer task invokes its `cargo` explicitly.

## Lab-only verification tools

Not part of any shipped build. Archives are fetched on a VM with egress, kept in `~/dist/tools/` on a build VM, and installed by the task that uses them, at user level only.

| Tool | Version | Source | sha256 |
|---|---|---|---|
| Java runtime (Eclipse Temurin JDK, for TLA+) | 21.0.13.1+2 | `https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13.1%2B2/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13.1_2.tar.gz` | `bb8a93f9ae6e7a693b2b721e85dbeff26ae1a77447985a8d7afcdd9c7cf6222e` (equals the published `.sha256.txt`) |
| TLA+ tools jar | v1.7.4 (release, not the 1.8 prerelease) | `https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar` | `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88` (release publishes none; computed on download) |
| `cargo-fuzz` | 0.13.2 | `https://static.crates.io/crates/cargo-fuzz/cargo-fuzz-0.13.2.crate` | `5acfd01930e49823e58c30dd8012d3338a620377d7c7d4cc140ca4b2169400e2` (crates.io checksum, verified) |
| `cargo-mutants` | 27.1.0 | `https://static.crates.io/crates/cargo-mutants/cargo-mutants-27.1.0.crate` | `07072e7bcdeb425d5e5fdbfd9f15a2c749e23cb2edf5ef40aee5876760ae1cf9` (crates.io checksum, verified) |
| `cargo-deny` | 0.22.2 | `https://static.crates.io/crates/cargo-deny/cargo-deny-0.22.2.crate` | `6ef2a6eee946dfa9dc44116568fd24130418e314c8b42b0a4cccd36425ee6121` (crates.io checksum, verified) |

Install steps (no root, no network on the build VM):

- **Java and TLA+.** `mkdir -p ~/opt && tar -xzf ~/dist/tools/jdk/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13.1_2.tar.gz -C ~/opt`, then run `~/opt/jdk-21.0.13.1+2/bin/java -cp ~/dist/tools/tla/tla2tools.jar tlc2.TLC <spec>` (SANY: `tla2sany.SANY`). Verify the sha256 of both files against this table first.
- **Cargo tools.** Their dependencies are vendored on the egress VM from the verified `.crate` (`tar -xzf <crate>`, then `cargo vendor --locked vendor` inside it, using that crate's own `Cargo.lock`) and tarred as `~/dist/tools/crates/<name>-<version>-vendored-src.tar.gz` (the tar itself is not reproducible; the `.crate` checksum above is what is pinned). On a build VM:

```
mkdir -p ~/opt/build/$N-$VER && tar -xzf ~/dist/tools/crates/$N-$VER-vendored-src.tar.gz -C ~/opt/build/$N-$VER
cd ~/opt/build/$N-$VER && mkdir .cargo
printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n' > .cargo/config.toml
PATH=$HOME/.rust/1.100.1/bin:$PATH cargo install --locked --offline --path . --root ~/opt/cargo-tools
```

  with `N`/`VER` as in the table; binaries land in `~/opt/cargo-tools/bin`. `cargo-fuzz` runs fuzz targets with the nightly above, not with the stable toolchain.
