[![tun2proxy](https://socialify.git.ci/tun2proxy/tun2proxy/image?description=1&language=1&name=1&stargazers=1&theme=Light)](https://github.com/tun2proxy/tun2proxy)

# tun2proxy
A tunnel interface for HTTP and SOCKS proxies on Linux, Android, macOS, iOS and Windows.

[![Crates.io](https://img.shields.io/crates/v/tun2proxy.svg)](https://crates.io/crates/tun2proxy)
[![tun2proxy](https://docs.rs/tun2proxy/badge.svg)](https://docs.rs/tun2proxy)
[![Documentation](https://img.shields.io/badge/docs-release-brightgreen.svg?style=flat)](https://docs.rs/tun2proxy)
[![Download](https://img.shields.io/crates/d/tun2proxy.svg)](https://crates.io/crates/tun2proxy)
[![License](https://img.shields.io/crates/l/tun2proxy.svg?style=flat)](https://github.com/tun2proxy/tun2proxy/blob/master/LICENSE)

> Additional information can be found in the [wiki](https://github.com/tun2proxy/tun2proxy/wiki)

## Features
- HTTP proxy support (unauthenticated, basic and digest auth)
- SOCKS4 and SOCKS5 support (unauthenticated, username/password auth)
- SOCKS4a and SOCKS5h support (through the virtual DNS feature)
- Minimal configuration setup for routing all traffic
- IPv4 and IPv6 support
- GFW evasion mechanism for certain use cases (see [issue #35](https://github.com/tun2proxy/tun2proxy/issues/35))
- SOCKS5 UDP support
- Native support for proxying DNS over TCP
- UdpGW (UDP gateway) support for UDP over TCP, see the [wiki](https://github.com/tun2proxy/tun2proxy/wiki/UDP-gateway-feature) for more information

## Build
Clone the repository and `cd` into the project folder. Then run the following:
```
cargo build --release
```

### Building Framework for Apple Devices
To build an XCFramework for macOS and iOS, run the following: 
```
./build-apple.sh
```

## Installation

### Install from binary

Download the binary from [releases](https://github.com/tun2proxy/tun2proxy/releases) and put it in your `PATH`.

<details>
  <summary>Authenticity Verification</summary>

Since v0.2.23 [build provenance attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds#verifying-artifact-attestations-with-the-github-cli)
are supported. These allow you to ensure that the builds have been generated from the code on GitHub through the GitHub
CI/CD pipeline. To verify the authenticity of the build files, you can use the [GitHub CLI](https://cli.github.com/):
```shell
gh attestation verify <*.zip file> --owner tun2proxy
```

</details>

### Install from source

If you have [rust](https://rustup.rs/) toolchain installed, this should work:
```shell
cargo install tun2proxy
```
> Note: In Windows, you need to copy [wintun](https://www.wintun.net/) DLL to the same directory as the binary.
> It's `%USERPROFILE%\.cargo\bin` by default.

## Setup
## Automated Setup
Using `--setup`, you can have tun2proxy configure your system to automatically route all traffic through the
specified proxy. This requires running the tool as root and will roughly perform the steps outlined in the section
describing the manual setup, except that a bind mount is used to overlay the `/etc/resolv.conf` file.

You would then run the tool as follows:
```bash
sudo ./target/release/tun2proxy-bin --setup --proxy "socks5://1.2.3.4:1080"
```

Apart from SOCKS5, SOCKS4 and HTTP are supported.

Note that if your proxy is a non-global IP address (e.g. because the proxy is provided by some tunneling tool running
locally), you will additionally need to provide the public IP address of the server through which the traffic is
actually tunneled. In such a case, the tool will tell you to specify the address through `--bypass <IP/CIDR>` if you
wish to make use of the automated setup feature.

## Manual Setup
A standard setup, which would route all traffic from your system through the tunnel interface, could look as follows:
```shell
# The proxy type can be either SOCKS4, SOCKS5 or HTTP.
PROXY_TYPE=SOCKS5
PROXY_IP=1.2.3.4
PROXY_PORT=1080
BYPASS_IP=123.45.67.89

# Create a tunnel interface named tun0 which you can bind to,
# so we don't need to run tun2proxy as root.
sudo ip tuntap add name tun0 mode tun
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

./target/release/tun2proxy-bin --tun tun0 --proxy "$PROXY_TYPE://$PROXY_IP:$PROXY_PORT"
```

This tool implements a virtual DNS feature that is used by switch `--dns virtual`. When a DNS packet to port 53 is detected, an IP
address from `198.18.0.0/15` is chosen and mapped to the query name. Connections destined for an IP address from that
range will supply the proxy with the mapped query name instead of the IP address. Since many proxies do not support UDP,
this enables an out-of-the-box experience in most cases, without relying on third-party resolvers or applications.
Depending on your use case, you may want to disable this feature using `--dns direct`.
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

Usage: tun2proxy-bin [OPTIONS] --proxy <URL> [ADMIN_COMMAND]...

Arguments:
  [ADMIN_COMMAND]...  Specify a command to run with root-like capabilities in the new namespace when using `--unshare`. This could be
                      useful to start additional daemons, e.g. `openvpn` instance

Options:
  -p, --proxy <URL>                        Proxy URL in the form proto://[username[:password]@]host:port, where proto is one of
                                           socks4, socks5, http. Username and password are encoded in percent encoding. For example:
                                           socks5://myname:pass%40word@127.0.0.1:1080
  -t, --tun <name>                         Name of the tun interface, such as tun0, utun4, etc. If this option is not provided, the
                                           OS will generate a random one
      --tun-fd <fd>                        File descriptor of the tun interface
      --close-fd-on-drop <true or false>   Set whether to close the received raw file descriptor on drop or not. This setting is
                                           dependent on [tun_fd] [possible values: true, false]
      --unshare                            Create a tun interface in a newly created unprivileged namespace while maintaining proxy
                                           connectivity via the global network namespace
      --unshare-pidfile <UNSHARE_PIDFILE>  Create a pidfile of `unshare` process when using `--unshare`
  -6, --ipv6-enabled                       IPv6 enabled
  -s, --setup                              Routing and system setup, which decides whether to setup the routing and system
                                           configuration. This option is only available on Linux and requires root-like privileges.
                                           See `capabilities(7)`
  -d, --dns <strategy>                     DNS handling strategy [default: direct] [possible values: virtual, over-tcp, direct]
      --dns-addr <IP>                      DNS resolver address [default: 8.8.8.8]
      --virtual-dns-pool <CIDR>            IP address pool to be used by virtual DNS in CIDR notation [default: 198.18.0.0/15]
  -b, --bypass <IP/CIDR>                   IPs used in routing setup which should bypass the tunnel, in the form of IP or IP/CIDR.
                                           Multiple IPs can be specified, e.g. --bypass 3.4.5.0/24 --bypass 5.6.7.8
      --tcp-timeout <seconds>              TCP timeout in seconds [default: 600]
      --udp-timeout <seconds>              UDP timeout in seconds [default: 10]
  -v, --verbosity <level>                  Verbosity level [default: info] [possible values: off, error, warn, info, debug, trace]
      --daemonize                          Daemonize for unix family or run as Windows service
      --exit-on-fatal-error                Exit immediately when fatal error occurs, useful for running as a service
      --max-sessions <number>              Maximum number of sessions to be handled concurrently [default: 200]
      --udpgw-server <IP:PORT>             UDP gateway server address, forwards UDP packets via specified TCP server
      --udpgw-connections <number>         Max connections for the UDP gateway, default value is 5
      --udpgw-keepalive <seconds>          Keepalive interval in seconds for the UDP gateway, default value is 30
  -h, --help                               Print help
  -V, --version                            Print version
```
Currently, tun2proxy supports HTTP, SOCKS4/SOCKS4a and SOCKS5. A proxy is supplied to the `--proxy` argument in the
URL format. For example, an HTTP proxy at `1.2.3.4:3128` with a username of `john.doe` and a password of `secret` is
supplied as `--proxy http://john.doe:secret@1.2.3.4:3128`. This works analogously to curl's `--proxy` argument.

## Container Support
### Docker
Tun2proxy can serve as a proxy for other Docker containers. To make use of that feature, first build the image:

```bash
docker build -t tun2proxy .
```

Next, start a container from the tun2proxy image:

```bash
docker run -d \
	-v /dev/net/tun:/dev/net/tun \
	--sysctl net.ipv6.conf.default.disable_ipv6=0 \
	--cap-add NET_ADMIN \
	--name tun2proxy \
	tun2proxy-bin --proxy proto://[username[:password]@]host:port
```

You can then provide the running container's network to another worker container by sharing the network namespace (like kubernetes sidecar):

```bash
docker run -it \
	--network "container:tun2proxy" \
	ubuntu:latest
```
### Docker Compose

The above docker command is written into a `docker-compose.yaml` file.

```yaml
services:
  tun2proxy:
    volumes:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      - net.ipv6.conf.default.disable_ipv6=0
    cap_add:
      - NET_ADMIN
    container_name: tun2proxy
    image: ghcr.io/tun2proxy/tun2proxy:latest
    command: --proxy proto://[username[:password]@]host:port
  alpine:
    stdin_open: true
    tty: true
    network_mode: container:tun2proxy
    image: alpine:latest
    command: apk add curl && curl ifconfig.icu && sleep 10
```

run compose file

```bash
docker compose up -d tun2proxy
docker compose up alpine
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

## Contributors ✨
Thanks goes to these wonderful people:

<a href="https://github.com/tun2proxy/tun2proxy/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=tun2proxy/tun2proxy" />
</a>
