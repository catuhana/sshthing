# sshthing

> [!IMPORTANT]
> The *optimisations* in the [`ByteSearch` and `SearchEngine`](src/key/mod.rs) are written by Claude Sonnet 4.

Mass-generate Ed25519 SSH keys until a word is found in its fields (private/public key, fingerprints, etc.).

## [Benchmark](BENCHMARK.md)

## Install

### Using Cargo

> [!NOTE]
> Nightly toolchain is required to build sshthing.

```
cargo install --git https://github.com/catuhana/sshthing
```

> [!TIP]
> To build against your CPU feature set, set `RUSTFLAGS` to `-Ctarget-cpu=native` before running the above command.

### [From GitHub Actions Artifacts](https://github.com/catuhana/sshthing/actions)

For every artifact an attestation is created, so you know builds are not tampered with.

> [!NOTE]
> Builds from GitHub Actions are not optimised for any specific CPU, so they will be slower than building it yourself with `RUSTFLAG`.

## Use

```
Usage: sshthing [OPTIONS] <KEYWORDS>...

Arguments:
  <KEYWORDS>...  The keywords to search for in SSH fields

Options:
  -f, --fields <FIELDS>    SSH fields to search in (default: sha256-fingerprint) [default: sha256-fingerprint] [possible values: private-key, public-key, sha256-fingerprint, sha512-fingerprint]
      --all-keywords       Require ALL keywords to match (default: any keyword matches)
      --all-fields         Require ALL fields to match (default: any field matches)
      --all                Search in all available fields
      --keys-only          Search only in key fields (private-key, public-key)
      --fingerprints-only  Search only in fingerprint fields (sha256, sha512)
      --no-keep-awake      Don't let your system stay awake while generating keys
  -t, --threads <THREADS>  Number of threads to use [default: 16]
  -h, --help               Print help
```
