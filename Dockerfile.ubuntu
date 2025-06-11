####################################################################################################
## Builder
####################################################################################################
FROM rust:latest AS builder

WORKDIR /worker
COPY ./ .
RUN cargo build --release


####################################################################################################
## Final image
####################################################################################################
FROM ubuntu:latest

RUN apt update && apt install -y iproute2 && apt clean all

COPY --from=builder /worker/target/release/tun2proxy-bin /usr/bin/tun2proxy-bin

ENTRYPOINT ["/usr/bin/tun2proxy-bin", "--setup"]
