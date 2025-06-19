####################################################################################################
# This is a multi-stage Dockerfile.
# Build with `docker buildx build -t <image-tag> --target <stage> .`
# For example, to build the Alpine-based image while naming it tun2proxy, run:
# `docker buildx build -t tun2proxy --target tun2proxy-alpine .`
####################################################################################################

####################################################################################################
## glibc builder
####################################################################################################
FROM rust:latest AS glibc-builder

    WORKDIR /worker
    COPY ./ .
    RUN cargo build --release

####################################################################################################
## musl builder
####################################################################################################
FROM rust:latest AS musl-builder

    WORKDIR /worker
    COPY ./ .
    RUN rustup target add x86_64-unknown-linux-musl 
    RUN cargo build --release --target x86_64-unknown-linux-musl

    RUN mkdir /.etc \
        && touch /.etc/resolv.conf \
        && mkdir /.tmp \
        && chmod 777 /.tmp \
        && chmod +t /.tmp

####################################################################################################
## Alpine image
####################################################################################################
FROM alpine:latest AS tun2proxy-alpine

    COPY --from=musl-builder /worker/target/x86_64-unknown-linux-musl/release/tun2proxy-bin /usr/bin/tun2proxy-bin

    ENTRYPOINT ["/usr/bin/tun2proxy-bin", "--setup"]

####################################################################################################
## Ubuntu image
####################################################################################################
FROM ubuntu:latest AS tun2proxy-ubuntu

    COPY --from=glibc-builder /worker/target/release/tun2proxy-bin /usr/bin/tun2proxy-bin

    ENTRYPOINT ["/usr/bin/tun2proxy-bin", "--setup"]

####################################################################################################
## OS-less image (default)
####################################################################################################
FROM scratch AS tun2proxy-scratch

    COPY --from=musl-builder ./tmp /tmp
    COPY --from=musl-builder ./etc /etc
    COPY --from=musl-builder /worker/target/x86_64-unknown-linux-musl/release/tun2proxy-bin /usr/bin/tun2proxy-bin

    ENTRYPOINT ["/usr/bin/tun2proxy-bin", "--setup"]
