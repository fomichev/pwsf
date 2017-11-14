# Installation

git clone ... rustup install nightly rustup default nightly cargo build

# Usage example

$ echo -n bogus12345 | cargo run -- -S -p ./simple.psafe3 list

# TODO

*   figure out error handling (essentially remove all unwrap())
*   cli wrapper (https://github.com/aweinstock314/rust-clipboard)
*   remove all debug prints
