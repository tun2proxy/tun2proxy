#! /bin/sh

echo "Setting up the rust environment..."
rustup target add aarch64-apple-ios
cargo install cbindgen

echo "Building target aarch64-apple-ios..."
cargo build --release --target aarch64-apple-ios --features mimalloc

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

echo "Creating XCFramework"
rm -rf ./tun2proxy.xcframework
xcodebuild -create-xcframework \
    -library ./target/aarch64-apple-ios/release/libtun2proxy.a -headers ./target/include/ \
    -output ./tun2proxy.xcframework
