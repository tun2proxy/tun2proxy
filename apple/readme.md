Build iOS framework
----------------

# Install Rust build tools

- Install Xcode Command Line Tools: `xcode-select --install`
- Install Rust programming language: `curl https://sh.rustup.rs -sSf | sh`
- Install iOS target support: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios`
- Install cbindgen tool: `cargo install cbindgen`

# Building iOS framework

Due to an unknown reason at present, compiling Rust code inside Xcode fails, so you have to manually compile it. Please run the following command in zsh (or bash):
```bash
cd tun2proxy

cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios
lipo -create target/aarch64-apple-ios/release/libtun2proxy.a target/x86_64-apple-ios/release/libtun2proxy.a -output target/libtun2proxy.a
cbindgen --config cbindgen.toml -l C -o target/tun2proxy-sys.h
```
