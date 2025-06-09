# sshthing

> [!IMPORTANT]
> VIBE CODE ALERT! Even though initially was entirely written by me, now parts of this code base (the *optimisations* in the [src/key.rs](src/key.rs)) are written by Claude Sonnet 4.

Mass-generate Ed25519 SSH keys until a word is found in its fields (private/public key, fingerprints, etc.).

## *Benchmark*

On average, generates

- 280_000 keys on an Intel i5-1240p
- 490_000 keys on a AMD Ryzen 5 7600
- ~~200_000 keys on an Apple Silicon M1 Max~~ (outdated, pending to update)
- ~~560_000 keys on an Apple Silicon M4 Max~~ (outdated, pending to update)

per second.

## Install

```
cargo install --git https://github.com/catuhana/sshthing
```

## Use

```
Usage: sshthing.exe [OPTIONS] <KEYWORDS>...

Arguments:
  <KEYWORDS>...  The keywords to search for in SSH fields

Options:
  -f, --fields <FIELDS>    SSH fields to search in (default: sha256-fingerprint) [default: sha256-fingerprint] [possible values: private-key, public-key, sha256-fingerprint, sha512-fingerprint]
      --all-keywords       Require ALL keywords to match (default: any keyword matches)
      --all-fields         Require ALL fields to match (default: any field matches)
  -t, --threads <THREADS>  Number of threads to use [default: 16]
      --all                Search in all available fields
      --keys-only          Search only in key fields (private-key, public-key)
      --fingerprints-only  Search only in fingerprint fields (sha256, sha512)
  -h, --help               Print help
```
