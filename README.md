# tun2proxy
A tunnel interface for HTTP and SOCKS proxies on Linux based on [smoltcp](https://github.com/smoltcp-rs/smoltcp).

## Features
- HTTP proxy support (unauthenticated, basic and digest auth)
- SOCKS4 and SOCKS5 support (unauthenticated, username/password auth)
- SOCKS4a and SOCKS5h support (through the virtual DNS feature)
- Minimal configuration setup for routing all traffic
- IPv4 and IPv6 support
- GFW evasion mechanism for certain use cases (see [issue #35](https://github.com/blechschmidt/tun2proxy/issues/35))
- SOCKS5 UDP support
- Native support for proxying DNS over TCP

## Build
Clone the repository and `cd` into the project folder. Then run the following:
```
cargo build --release
```

## Setup
## Automated Setup
Using `--setup auto`, you can have tun2proxy configure your system to automatically route all traffic through the
specified proxy. This requires running the tool as root and will roughly perform the steps outlined in the section
describing the manual setup, except that a bind mount is used to overlay the `/etc/resolv.conf` file.

You would then run the tool as follows:
```bash
sudo ./target/release/tun2proxy --setup auto --proxy "socks5://1.2.3.4:1080"
```

Apart from SOCKS5, SOCKS4 and HTTP are supported.

Note that if your proxy is a non-global IP address (e.g. because the proxy is provided by some tunneling tool running
locally), you will additionally need to provide the public IP address of the server through which the traffic is
actually tunneled. In such a case, the tool will tell you to specify the address through `--bypass-ip <address>` if you
wish to make use of the automated setup feature.

## Manual Setup
A standard setup, which would route all traffic from your system through the tunnel interface, could look as follows:
```shell
# The proxy type can be either SOCKS4, SOCKS5 or HTTP.
PROXY_TYPE=SOCKS5
PROXY_IP=1.2.3.4
PROXY_PORT=1080
BYPASS_IP=123.45.67.89

# Create a tunnel interface named tun0 which your user can bind to,
# so we don't need to run tun2proxy as root.
sudo ip tuntap add name tun0 mode tun user $USER
sudo ip link set tun0 up

# To prevent a routing loop, we add a route to the proxy server that behaves
# like the default route.
sudo ip route add "$BYPASS_IP" $(ip route | grep '^default' | cut -d ' ' -f 2-)

# Route all your traffic through tun0 without interfering with the default route.
sudo ip route add 128.0.0.0/1 dev tun0
sudo ip route add 0.0.0.0/1 dev tun0

# If you wish to also route IPv6 traffic through the proxy, these two commands will do.
sudo ip route add ::/1 dev tun0
sudo ip route add 8000::/1 dev tun0

# Make sure that DNS queries are routed through the tunnel.
sudo sh -c "echo nameserver 198.18.0.1 > /etc/resolv.conf"

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
  -t, --tun <name>         Name of the tun interface [default: tun0]
      --tun-fd <fd>        File descriptor of the tun interface
      --tun-mtu <mtu>      MTU of the tun interface (only with tunnel file descriptor) [default: 1500]
  -p, --proxy <URL>        Proxy URL in the form proto://[username[:password]@]host:port
  -d, --dns <strategy>     DNS handling strategy [default: virtual] [possible values: virtual, over-tcp, direct]
      --dns-addr <IP>      DNS resolver address [default: 8.8.8.8]
  -6, --ipv6-enabled       IPv6 enabled
  -s, --setup <method>     Routing and system setup [possible values: auto]
      --bypass-ip <IP>     Public proxy IP used in routing setup which should bypassing the tunnel
  -v, --verbosity <level>  Verbosity level [default: info] [possible values: off, error, warn, info, debug, trace]
  -h, --help               Print help
  -V, --version            Print version
```
Currently, tun2proxy supports HTTP, SOCKS4/SOCKS4a and SOCKS5. A proxy is supplied to the `--proxy` argument in the
URL format. For example, an HTTP proxy at `1.2.3.4:3128` with a username of `john.doe` and a password of `secret` is
supplied as `--proxy http://john.doe:secret@1.2.3.4:3128`. This works analogously to curl's `--proxy` argument.

## Docker Support
Tun2proxy can serve as a proxy for other Docker containers. To make use of that feature, first build the image:

```bash
docker build -t tun2proxy .
```

Next, start a container from the tun2proxy image:

```bash
docker run -d \
	-e PROXY=PROXY_TYPE://PROXY_IP:PROXY_PORT \
	-v /dev/net/tun:/dev/net/tun \
	--sysctl net.ipv6.conf.all.disable_ipv6=0 \
	--sysctl net.ipv6.conf.default.disable_ipv6=0 \
	--cap-add NET_ADMIN \
	--name tun2proxy \
	tun2proxy
```

You can then provide the running container's network to another worker container by sharing the network namespace:

```bash
docker run -it \
	-d \
	--network "container:tun2proxy" \
	ubuntu:latest
```

## Configuration Tips
### DNS
When DNS resolution is performed by a service on your machine or through a server in your local network, DNS resolution
will not be performed through the tunnel interface, since the routes to localhost or your local network are more
specific than `0.0.0.0/1` and `128.0.0.0/1`.
In this case, it may be advisable to update your `/etc/resolv.conf` file to use a nameserver address that is routed
through the tunnel interface. When virtual DNS is working correctly, you will see log messages like
`DNS query: example.org` for hostnames which your machine is connecting to after having resolved them through DNS.

Note that software like the `NetworkManager` may change the `/etc/resolv.conf` file automatically at any time, which
will result in DNS leaks. A hacky solution to prevent this consists in making the file immutable as follows:
`sudo chattr +i "$(realpath /etc/resolv.conf)"`.

### IPv6
Some proxy servers might not support IPv6. When using virtual DNS, this is not a problem as DNS names are resolved by
the proxy server. When DNS names are resolved to IPv6 addresses locally, this becomes a problem as the proxy will be
asked to open connections to IPv6 destinations. In such a case, you can disable IPv6 on your machine. This can be done
either through `sysctl -w net.ipv6.conf.all.disable_ipv6=1` and `sysctl -w net.ipv6.conf.default.disable_ipv6=1`
or through `ip -6 route del default`, which causes the `libc` resolver (and other software) to not issue DNS AAAA
requests for IPv6 addresses.
