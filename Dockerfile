####################################################################################################
## Builder
####################################################################################################
FROM rust:latest AS builder

WORKDIR /worker
COPY ./ .
RUN cargo build --release --target x86_64-unknown-linux-gnu


####################################################################################################
## Final image
####################################################################################################
FROM ubuntu:latest

RUN apt update && apt install -y iproute2 && apt clean all

COPY --from=builder /worker/target/x86_64-unknown-linux-gnu/release/tun2proxy /usr/bin/tun2proxy

ENTRYPOINT ["/usr/bin/tun2proxy", "--setup", "auto"]
