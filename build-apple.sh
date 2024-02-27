#! /bin/sh

echo "Setting up the rust environment..."
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios x86_64-apple-darwin aarch64-apple-darwin
cargo install cbindgen

echo "Building..."
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios
cargo build --release --target aarch64-apple-ios-sim

echo "Generating includes..."
mkdir -p target/include/
cbindgen --config cbindgen.toml -l C -o target/include/tun2proxy.h
cat > target/include/module.modulemap <<EOF
framework module Tun2Proxy {
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
rm -rf ./target/Tun2Proxy.xcframework
xcodebuild -create-xcframework \
-library ./target/aarch64-apple-ios/release/libtun2proxy.a -headers ./target/include/ \
-library ./target/libtun2proxy-ios-sim.a -headers ./target/include/ \
-library ./target/libtun2proxy-macos.a -headers ./target/include/ \
-output ./target/Tun2Proxy.xcframework
