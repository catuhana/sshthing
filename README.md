# sshthing

> [!IMPORTANT]
> The *optimisations* in the [src/key.rs](src/key.rs) are written by Claude Sonnet 4.

Mass-generate Ed25519 SSH keys until a word is found in its fields (private/public key, fingerprints, etc.).

## *Benchmark*

> [!TIP]
> I would be grateful if you've contributed your benchmarks here!
> 1. Close some *heavy* apps running in the background. Apps like Discord, or your browser and etc. is fine.
> 2. Run with `hello,this,is,averylongtext,withsomanyargumentsicanttakeitanymomre --all --all-keywords --all-fields` inputs
> 3. Let it run for around 2-5 minutes
> 4. Add the average keys/s below in the same format

On average, generates

- 282_070 keys on an Intel i5-1240p
- 490_000 keys on an AMD Ryzen 5 7600
- ~~200_000 keys on an Apple Silicon M1 Max~~ (outdated, pending to update)
- ~~560_000 keys on an Apple Silicon M4 Max~~ (outdated, pending to update)

per second.

## Install

```
cargo install --git https://github.com/catuhana/sshthing
```

> [!TIP]
> To build against your CPU feature set, set `RUSTFLAGS` to `-Ctarget-cpu=native` before running the above command.

## Use

```
Usage: sshthing.exe [OPTIONS] <KEYWORDS>...

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
