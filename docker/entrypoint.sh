#!/bin/bash


run() {
  if [ -n "$TUN" ]; then
    TUN="--tun $TUN"
  fi

  if [ -n "$PROXY" ]; then
    PROXY="--proxy $PROXY"
  fi

  if [ -n "$DNS" ]; then
    DNS="--dns $DNS"
  fi

  if [ -n "$BYPASS_IP" ]; then
    BYPASS_IP="--bypass $BYPASS_IP"
  fi

  if [ -n "$VERBOSITY" ]; then
    VERBOSITY="-v $VERBOSITY"
  fi

  if [ -n "$MODE" ]; then
    MODE="--setup $MODE"
  fi

  echo "Bootstrap ready!! Exec Command: tun2proxy $TUN $PROXY $DNS $VERBOSITY $MODE $BYPASS_IP $@"

  exec tun2proxy $TUN $PROXY $DNS $VERBOSITY $MODE $BYPASS_IP $@
}


run $@ || echo "Runing ERROR!!"
