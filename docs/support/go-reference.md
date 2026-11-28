# Go reference

The Rust rewrite (decision D109) is checked against the final Go tree. That tree is frozen here as the reference
and test oracle: its behavior, its tests, its binaries and its conformance inputs.

## Identity

| What | Value |
|---|---|
| Branch | `go-reference` (made from `11f21e6`, one commit on top) |
| Reference commit | `b0db3cbdbd38f024e5960eb4153c63ed490c9a8a` |
| Tag | `go-reference-2026-11-29` (signed, tag object `3e12ff8ffdc1545edf5047647da1561eb24e0203`) |
| Source digest (`go run ./build source-digest`) | `9c0ff4c105a88d6631f56a91eeb9fefc65761f1a731a2d80903fc76cc6149e3c` |
| Build id of the binaries | `sha256:9c0ff4c105a88d6631f56a91eeb9fefc65761f1a731a2d80903fc76cc6149e3c+ui:9e6b4834dce71b5d` |
| Go | `go1.27.3 linux/amd64` (the pinned toolchain; archive sha256 `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`) |

Content of the commit: `11f21e6` plus the uncommitted admission, BeginFix, CutFix, AdmitFlakes, ctllane, qg4 and rules
lanes (260 paths: 140 new, 120 modified; decisions D104 to D108). The six unbuilt edits the stopped IntegFix lane left
are not in it. The commit message lists what is unverified; in short: two open flakes
(`TestAPolicyWriteIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntake` under `-race`, 2 of 11;
`TestMixedBinaryPreviousReleaseVoterOnAFreshInstallation` 503 once, then 3 of 3), the distributed and queries gates
unmeasured, the LogQL read-back 504 question, and the protocol-5 declaration after a rolling upgrade from 1.0.0.

`feat/implement-approved-soundpost` contains `go-reference` (merge commit), so the in-tree Go code equals the reference.

## Binaries

Built from the reference commit on one lab VM, `GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off`,
`SOUNDPOST_GO` set to the unpacked pinned Go, `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`.
Lab path: `/home/sp/goref/b0db3cb/` (`bin/` holds the three binaries and `SHA256SUMS`; `rel/` the full release tree;
`release-manifest.json`; `SOURCE-DIGEST`).

| Binary | Build command | sha256 |
|---|---|---|
| `soundpost` (plain) | `go run ./build release --out OUT/rel --version 1.0.1 --arch amd64 --web-dist UI --archive go1.27.3.linux-amd64.tar.gz --reproduce` | `cdd7f82b3d3fe52e965142e034ca26faf7e3ecb4de56c88403d635e4d99f19ac` |
| `soundpost_diag` | `go build -trimpath -buildvcs=false -mod=readonly -tags=netgo,osusergo,webembed,soundpost_diag "-ldflags=-s -w -buildid= -X main.version=1.0.1 -X main.commit=<commit> -X main.buildID=<build id>" -o OUT/soundpost_diag/soundpost ./cmd/soundpost` | `171d464435129282265e569d66127c18f9a29dce607bc0a1a6c8dc2e2f6410ae` |
| `soundpost_faults` | the same with `-tags=netgo,osusergo,webembed,soundpost_faults` | `867f6b46920564de704a114886abe51af22acfab187453bc2a68d818a2b234cb` |

The two tagged builds use exactly the flags `build/release.go` uses for the plain build (`buildPlan.flags`), plus one tag;
`go run ./build release` has no tag option, so they are plain `go build` runs after the UI bundle is staged in
`cmd/soundpost/webdist` (the staging is removed afterwards). `<commit>` and `<build id>` are the values in the table
above. The release also built `soundpost-agent` (`2f14a4095e8ba76162d1069a96e17350d0d7811b1185c97181a2a4dd06f8275c`) and
`soundpost-perf-acquire` (`305ef050dc0e21488a8985cebdc1ce58c7af8f6589abd9b970d276fae992f6f2`). `--reproduce` built the
release twice with empty caches and the sha256 of every binary was equal.

UI bundle caveat: the web UI embedded in these binaries (5 files, tree sha256
`9e6b4834dce71b5d7470165db5fa262d8ef7921c18e6e0a179c20b4e223ecf04`) is the `web/dist` the owner's tree already had (written
2026-11-10). It was not rebuilt for this freeze and its match with the `web/` sources of the reference was not verified.
The delta from `11f21e6` to the reference touches nothing under `web/` or `packages/`. [INFERENCE] The UI bundle does not
change the API, storage or protocol behavior the Rust rewrite is compared against.

## Conformance reference did not move

The sha256 of the conformance inputs and the image digests they pin are identical on `11f21e6` and on `go-reference`.
These digests are the Rust conformance reference.

| File | sha256 |
|---|---|
| `conformance/query/source-lock.json` | `69f1b0939ab65a59ae6dfcc0ea814c8140e00f42013bb680594ef41191bf9036` |
| `conformance/query/provenance.json` | `c984b285a01ff6c443e17257a1cb2fa1f91ab41034dd07bc9af83d5fc886a3a6` |
| `conformance/query/oracles/logql-loki-3.5.2.Dockerfile` | `6c25f48d5822842785c42a3f51198e80c36a71e90cd867eaae5647004ac1ba6a` |
| `conformance/query/oracles/promql-prometheus-3.1.0-configuration.Dockerfile` | `06542ea58f72247bd309d9aa8020719097ccc2a35c69eb57948204f8a0784f2a` |
| `conformance/query/oracles/promql-prometheus-3.1.0.Dockerfile` | `712f31a3c0b63a0959b192ef18b9cceb2e21a608ed6e4aed42496344da634fb5` |
| `conformance/query/oracles/promql-prometheus-3.13.5-configuration.Dockerfile` | `58c9ec9b54480993b5692b0aa57b13ff13069920ac2d6777c771ca27ad58123b` |
| `conformance/query/oracles/promql-prometheus-3.13.5.Dockerfile` | `9a30e0dc3b052d4cbe91698a8bc9c58277c70d062e1b000c4a9e1689133fbf78` |

The 19 distinct `sha256:` digests found in those seven files (`grep -oE 'sha256:[0-9a-f]{64}'`, sorted, unique), the same
set on both revisions:

```
0db690662744694667c031a81d3e20cdd3a68a387a8050c8096bebbdf2ff8db2
116d51d5458ca0fea8696425fd475fd4211eb831b350e831649a264afe221b05
1762aa90ae2016f5ce23ab566a17e15ecb6ae4a71101dc801a3f92510bc1730d
1a394b385e1fca89a6b81eab782074de26c5d35fccdebfef15c68daa55029de5
1f2f79b4dd8c1d4ecee0d0cec6471f633324eebc01924f8e4fa4c2742ef2bf4f
5ce19138fad8f18ecec1fd3517af78daacdfdcce050f38019de835cb71bd953e
6234d450fe5c3770af5c0a3d20adff668e4594d3abd626a29d626a73ab69d417
6559acbd5d770b15bb3c954629ce190ac3cbbdb2b7f1c30f0385c4e05104e218
670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c
8987588ebc5a27101cb9e71595511217991a30aa2690fa09204e7815ea108563
9820aca42262f58451f006de3213055974b36f24b31508c1baa73c967fcecb99
aafa9d694e6a883c02db516d9f6e5b84e14195f49a2a6456a4cca815edda72b9
c2f96e97afede2cb4b43266bf62d964bed9194c7a1ac37759e1c6fd68600b410
d0a95e651bb7d0a5a6468035c5b49c52f4678d90d598f853c06716bca102686b
d12ab5b1cd7ac58c1c0ea8cb43e0d151d1d5bee1cb897c7e7eaf225adae07928
d958db557400fc52e8aad82b5fa0cad15d8d270105fd56a4d1615d013778abe3
da1630c5102817ed365a523448c766e417030a53ec3dfbe064d429df504e023e
dc30314819e04a1a3d18d0b37eaa9c8e4e18f33f026e3e2d81bf127c7cddcd55
ef5b4be1f94b36c90385abd9b6b4f201723ae28e71acacb76d00687333c17282
```

## Using the reference

- Phase 1 fixtures (Fault JSON, `HashCanonical`) are generated from this commit on a lab VM; record `b0db3cb` with them.
- Task 0.6 (limiting the existing Go workflows to `go-reference`) is a separate task and is not done by this freeze.
- Nothing in this file was measured by running the Go test suite: the freeze itself ran no tests.
