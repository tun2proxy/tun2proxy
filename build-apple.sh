#! /bin/sh

echo "Setting up the rust environment..."
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios x86_64-apple-darwin aarch64-apple-darwin
cargo install cbindgen

echo "Building..."

echo "cargo build --release --target x86_64-apple-darwin"
cargo build --release --target x86_64-apple-darwin

echo "cargo build --release --target aarch64-apple-darwin"
cargo build --release --target aarch64-apple-darwin

echo "cargo build --release --target aarch64-apple-ios"
cargo build --release --target aarch64-apple-ios --features mimalloc

echo "cargo build --release --target x86_64-apple-ios"
cargo build --release --target x86_64-apple-ios

echo "cargo build --release --target x86_64-apple-ios-sim"
cargo build --release --target aarch64-apple-ios-sim

echo "Generating includes..."
mkdir -p target/include/
rm -rf target/include/*
cbindgen --config cbindgen.toml -o target/include/tun2proxy.h
cat > target/include/tun2proxy.modulemap <<EOF
framework module tun2proxy {
    umbrella header "tun2proxy.h"
    export *
    module * { export * }
}
EOF

echo "lipo..."

echo "Simulator"
lipo -create \
    target/aarch64-apple-ios-sim/release/libtun2proxy.a \
    target/x86_64-apple-ios/release/libtun2proxy.a \
    -output ./target/libtun2proxy-ios-sim.a

echo "MacOS"
lipo -create \
    target/aarch64-apple-darwin/release/libtun2proxy.a \
    target/x86_64-apple-darwin/release/libtun2proxy.a \
    -output ./target/libtun2proxy-macos.a

echo "Creating XCFramework"
rm -rf ./tun2proxy.xcframework
xcodebuild -create-xcframework \
    -library ./target/aarch64-apple-ios/release/libtun2proxy.a -headers ./target/include/ \
    -library ./target/libtun2proxy-ios-sim.a -headers ./target/include/ \
    -library ./target/libtun2proxy-macos.a -headers ./target/include/ \
    -output ./tun2proxy.xcframework
