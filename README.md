# tun2proxy
Tunnel TCP traffic through SOCKS5 or HTTP on Linux.

**Error handling incomplete and too restrictive.**

## Build
Clone the repository and `cd` into the project folder. Then run the following:
```
cargo build --release
```

## Setup
A standard setup, which would route all traffic from your system through the tunnel interface, could look as follows:
```shell
# The proxy type can be either SOCKS5 or HTTP.
PROXY_TYPE=SOCKS5
PROXY_IP=1.2.3.4
PROXY_PORT=1080

# Create a tunnel interface named tun0 which your user can bind to,
# so we don't need to run tun2proxy as root.
sudo ip tuntap add name tun0 mode tun user $USER
sudo ip link set tun0 up

# To prevent a routing loop, we add a route to the proxy server that behaves
# like the default route.
sudo ip route add "$PROXY_IP" $(ip route | grep '^default' | cut -d ' ' -f 2-)

# Route all your traffic through tun0 without interfering with the default route.
sudo ip route add 128.0.0.0/1 dev tun0
sudo ip route add 0.0.0.0/1 dev tun0

./target/release/tun2proxy --tun tun0 --proxy "$PROXY_TYPE://$PROXY_IP:$PROXY_PORT"
```

Note that if you paste these commands into a shell script, which you then run with `sudo`, you might want to replace
`$USER` with `$SUDO_USER`.

This tool implements a virtual DNS feature that is used by default. When a DNS packet to port 53 is detected, an IP
address from `198.18.0.0/15` is chosen and mapped to the query name. Connections destined for an IP address from that
range will supply the proxy with the mapped query name instead of the IP address. Since many proxies do not support UDP,
this enables an out-of-the-box experience in most cases, without relying on third-party resolvers or applications.
Depending on your use case, you may want to disable this feature using `--dns none`.
In that case, you might need an additional tool like [dnsproxy](https://github.com/AdguardTeam/dnsproxy) that is
configured to listen on a local UDP port and communicates with a third-party upstream DNS server via TCP.

When you terminate this program and want to eliminate the impact caused by the above several commands,
you can execute the following command. The routes will be automatically deleted with the tunnel device.
```shell
sudo ip link del tun0
```

## CLI
```
Tunnel interface to proxy.

Usage: tun2proxy [OPTIONS] --proxy <URL>

Options:
  -t, --tun <name>    Name of the tun interface [default: tun0]
  -p, --proxy <URL>   Proxy URL in the form proto://[username[:password]@]host:port
  -d, --dns <method>  DNS handling [default: virtual] [possible values: virtual, none]
  -h, --help          Print help
  -V, --version       Print version
```
Currently, tun2proxy supports two proxy protocols: HTTP and SOCKS5. A proxy is supplied to the `--proxy` argument in the
URL format. For example, an HTTP proxy at `1.2.3.4:3128` with a username of `john.doe` and a password of `secret` is
supplied as `--proxy http://john.doe:secret@1.2.3.4:3128`. This works analogously to curl's `--proxy` argument.

## TODO
- Improve handling of half-open connections
- Increase error robustness (reduce `unwrap` and `expect` usage)
- UDP support for SOCKS
- SOCKS4/SOCKS4a support
- Native support for proxying DNS over TCP or TLS
