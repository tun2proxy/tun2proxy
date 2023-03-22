FROM alpine:edge
RUN apk add --no-cache cargo rust pkgconfig openssl-dev
RUN mkdir /tun2proxy
ADD src /tun2proxy/src
ADD Cargo.toml /tun2proxy/Cargo.toml
ADD tests /tun2proxy/tests
WORKDIR /tun2proxy
RUN cargo build --tests
ENTRYPOINT ["cargo", "test"]
