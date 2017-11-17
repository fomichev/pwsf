# Installation

```
git clone ...
rustup install nightly
rustup default nightly
cargo build
```

# Usage example

```
$ echo bogus12345 | cargo run -- -S -p ./simple.psafe3 list

$ echo bogus12345 | cargo run -- -S -p ./simple.psafe3 show "(Four|Five)"

echo -e "bogus12345\n1" | cargo run -- -S -p ./simple.psafe3 copy "(Four|Five)"
```
