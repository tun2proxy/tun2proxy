#! /usr/bin/bash -x

# Please set the following parameters according to your environment
# BYPASS_IP=123.45.67.89
PROXY_IP=127.0.0.1
PROXY_PORT=1080
PROXY_TYPE=SOCKS5

function core_function() {
    local is_envonly="${1}"
    local bypass_ip="${2}"

    sudo ip tuntap add name tun0 mode tun
    sudo ip link set tun0 up

    sudo ip route add "${bypass_ip}" $(ip route | grep '^default' | cut -d ' ' -f 2-)

    sudo ip route add 128.0.0.0/1 dev tun0
    sudo ip route add 0.0.0.0/1 dev tun0

    sudo ip route add ::/1 dev tun0
    sudo ip route add 8000::/1 dev tun0

    sudo sh -c "echo nameserver 198.18.0.1 > /etc/resolv.conf"

    if [ "$is_envonly" = true ]; then
        read -n 1 -s -r -p "Don't do anything. If you want to exit and clearup environment, press any key..."
        echo ""
        restore
    else
        trap 'echo "" && echo "tun2proxy exited with code: $?" && restore' EXIT
        local SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        local APP_BIN_PATH="${SCRIPT_DIR}/../target/release/tun2proxy-bin"
        "${APP_BIN_PATH}" --tun tun0 --proxy "${PROXY_TYPE}://${PROXY_IP}:${PROXY_PORT}" -v trace
    fi
}

function restore() {
    sudo ip link del tun0
    sudo systemctl restart systemd-resolved.service
}

function main() {
    local action=${1}
    # [ -z ${1} ] && action="envonly"

    local bypass_ip=${2}
    # [ -z ${2} ] && bypass_ip="123.45.67.89"

    case "${action}" in
        envonly)
            core_function true "${bypass_ip}"
            ;;
        tun2proxy)
            core_function false "${bypass_ip}"
            ;;
        *)
            echo "Arguments error! [${action}]"
            echo "Usage: `basename $0` [envonly|tun2proxy] [bypass_ip]"
            ;;
    esac

    exit 0
}

main "$@"
