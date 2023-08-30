#!/bin/bash


run() {
  if [ -n "$BYPASS_IP" ]; then
    BYPASS_IP="--bypass-ip $BYPASS_IP"
  fi

  if [ -n "$DNS" ]; then
    DNS="--dns $DNS"
  fi

  if [ -n "$MODE" ]; then
    MODE="--setup $MODE"
  fi

  if [ -n "$PROXY" ]; then
    PROXY="--proxy $PROXY"
  fi

  if [ -n "$TUN" ]; then
    TUN="--tun $TUN"
  fi

  exec tun2proxy $TUN $PROXY $DNS $MODE $BYPASS_IP
}


run || echo "Runing ERROR!!"
