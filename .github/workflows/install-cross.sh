#!/bin/bash

curl -s https://api.github.com/repos/cross-rs/cross/releases/latest \
    | grep cross-x86_64-unknown-linux-gnu.tar.gz \
    | cut -d : -f 2,3 \
    | tr -d \" \
    | wget -qi -

tar -zxvf cross-x86_64-unknown-linux-gnu.tar.gz -C /usr/bin
rm -f cross-x86_64-unknown-linux-gnu.tar.gz

