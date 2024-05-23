#! /bin/bash

work_dir=$(pwd)

export ANDROID_HOME=/tmp/Android/sdk
export NDK_HOME=${ANDROID_HOME}/ndk/25.2.9519653
export PATH=$ANDROID_HOME/cmdline-tools/bin:$PATH
mkdir -p $ANDROID_HOME

name=tun2proxy
package=tun2proxy
BASE=`dirname "$0"`
android_libs=$BASE/${name}-android-libs
mkdir -p $android_libs

function setup_env() {
    cargo install cbindgen
    apt update && apt install -y make llvm-dev libclang-dev clang pkg-config zip unzip curl default-jdk build-essential
    cd /tmp/
    curl -OL https://dl.google.com/android/repository/commandlinetools-linux-6858069_latest.zip
    rm -rf /tmp/cmdline-tools
    unzip commandlinetools-linux-6858069_latest.zip
    rm -rf $ANDROID_HOME/cmdline-tools
    mv cmdline-tools $ANDROID_HOME
    yes | sdkmanager --sdk_root=$ANDROID_HOME --licenses
    sdkmanager --sdk_root=$ANDROID_HOME "ndk;25.2.9519653" "platforms;android-21"
}

function build_android() {
    local manifest=./Cargo.toml
    local mode=--release
    local mode2=release
    local targets=

    if [ ! -z "$2" ]; then
        targets="$2"
    else
        targets="aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android"
    fi

    for target in $targets; do
        rustup target add $target
    done

    if [ "$1" = "debug" ]; then
        mode=
        mode2=debug
    fi

    local BASE=`dirname "$0"`
    local HOST_OS=`uname -s | tr "[:upper:]" "[:lower:]"`
    local HOST_ARCH=`uname -m | tr "[:upper:]" "[:lower:]"`

    export PATH="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin/":$PATH

    local android_tools="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin"
    local api=21

    for target in $targets; do
        local target_dir=
        case $target in
            'armv7-linux-androideabi')
                export CC_armv7_linux_androideabi="$android_tools/armv7a-linux-androideabi${api}-clang"
                export AR_armv7_linux_androideabi="$android_tools/llvm-ar"
                export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$android_tools/armv7a-linux-androideabi${api}-clang"
                target_dir=armeabi-v7a
                ;;
            'x86_64-linux-android')
                export CC_x86_64_linux_android="$android_tools/${target}${api}-clang"
                export AR_x86_64_linux_android="$android_tools/llvm-ar"
                export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"
                target_dir=x86_64
                ;;
            'aarch64-linux-android')
                export CC_aarch64_linux_android="$android_tools/${target}${api}-clang"
                export AR_aarch64_linux_android="$android_tools/llvm-ar"
                export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"
                target_dir=arm64-v8a
                ;;
            'i686-linux-android')
                export CC_i686_linux_android="$android_tools/${target}${api}-clang"
                export AR_i686_linux_android="$android_tools/llvm-ar"
                export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"
                target_dir=x86
                ;;
            *)
                echo "Unknown target $target"
                ;;
        esac
        cargo build --target $target $mode
        mkdir -p $android_libs/$target_dir
        cp $BASE/target/$target/${mode2}/lib${name}.so $android_libs/${target_dir}/lib${name}.so
    done

    cbindgen -c $BASE/cbindgen.toml -l C --cpp-compat -o $android_libs/$name.h
}

function main() {
    echo "Setting up the build environment..."
    setup_env
    cd $work_dir

    echo "build android target"
    build_android "$@"
    cd $work_dir

    echo "Creating zip file"
    rm -rf ${name}-android-libs.zip
    zip -r ${name}-android-libs.zip ${name}-android-libs
}

main "$@"

