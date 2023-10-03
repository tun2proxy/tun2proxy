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
WORKDIR /app

ENV TUN=tun0
ENV PROXY=
ENV DNS=virtual
ENV MODE=auto
ENV BYPASS_IP=

RUN apt update && apt install -y iproute2 curl && apt clean all

COPY --from=builder /worker/target/x86_64-unknown-linux-gnu/release/tun2proxy /usr/bin/tun2proxy
COPY --from=builder /worker/docker/entrypoint.sh /app

ENTRYPOINT ["/app/entrypoint.sh"]
