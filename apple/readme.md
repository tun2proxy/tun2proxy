Build iOS xcframework
----------------

# Install Rust build tools

- Install Xcode Command Line Tools: `xcode-select --install`
- Install Rust programming language: `curl https://sh.rustup.rs -sSf | sh`
- Install iOS target support: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios`
- Install cbindgen tool: `cargo install cbindgen`

# Building iOS xcframework

Run the following command in zsh (or bash):
```bash
cd tun2proxy
./build-apple.sh
```

The script `build-apple.sh` will build the iOS/macOS xcframework and output it to `./tun2proxy.xcframework`

To save the build time, you can use the `build-aarch64-apple-ios-debug.sh` or `build-aarch64-apple-ios.sh` script
to build the `aarch64-apple-ios` target only.
