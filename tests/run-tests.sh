#!/bin/bash
#
# Run as follows:
# sudo SOCKS5_SERVER=<ip>:<port> HTTP_SERVER=<ip>:<port> ./run-tests.sh
#
# Alternatively, `cargo test` can be used instead of `./run-tests.sh`.
# Note that the tests require root privileges and will change
# the system's default routes.

SCRIPT_DIR="$(dirname "$0")"
cd "$SCRIPT_DIR/.."
docker build -t tun2proxy-tests -f tests/Dockerfile . && docker run -e SOCKS5_SERVER -e HTTP_SERVER --rm -it tun2proxy-tests
