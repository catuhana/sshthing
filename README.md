# sshthing

Mass-generate Ed25519 SSH keys until a word is found in its fields (private/public key, fingerprints, etc.).

On average, generates 130_000 keys on i5-1240p and 200_000 keys on M1 Max per second.

## Install

```
cargo install --git https://github.com/catuhana/sshthing
```

## Use

```
Usage: sshthing.exe [OPTIONS] --keywords <KEYWORDS>

Options:
  -K, --keywords <KEYWORDS>
          The keywords to search for in SSH fields
  -S, --search-in <SEARCH_IN>
          Generated SSH fields to search in [default: sha256-fingerprint]
      --keywords-match-mode <KEYWORDS_MATCH_MODE>
          Match mode for keywords [default: all]
      --search-match-mode <SEARCH_MATCH_MODE>
          Match mode for search fields [default: all]
  -t, --threads <THREADS>
          The number of threads to use [default: 16]
  -h, --help
          Print help
```

```sh
# Look for `meow` keyword in SHA256 fingerprint field.
sshthing --keywords meow
# Look for `meow` and `mrrp` keywords in all fields, matching all keywords
sshthing --keywords meow,mrrp --search-in all
# Look for `meow` and `mrrp` keywords in any of private & public keys, matching all keywords
sshthing --keywords meow,mrrp --search-in keys --search-match-mode any
# Look for `meow` and `mrrp` keywords in all fields, matching any keyword
sshthing --keywords meow-mrrp --search-in all --keywords-match-mode any
# ...
```
