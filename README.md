# tun2proxy
Tunnel TCP traffic through SOCKS5 or HTTP on Linux.

**Authentication not yet supported. Error handling incomplete and too restrictive.**

## Build
Clone the repository and `cd` into the project folder. Then run the following:
```
cargo build --release
```

## Setup
A standard setup, which would route all traffic from your system through the tunnel interface, could look as follows:
```shell
# Define the proxy endpoint.
PROXY_IP=1.2.3.4
PROXY_PORT=1080

# Create a tunnel interface named tun0 which your user can bind to, so we don't need to run tun2proxy as root.
sudo ip tuntap add name tun0 mode tun user $USER
sudo ip link set tun0 up

# To prevent a routing loop, we add a route to the proxy server that behaves like the default route.
sudo ip route add "$PROXY_IP" $(ip route | grep '^default' | cut -d ' ' -f 2-)

# Route all your traffic through tun0 without interfering with the default route.
sudo ip route add 128.0.0.0/1 dev tun0
sudo ip route add 0.0.0.0/1 dev tun0

./target/release/tun2proxy --tun tun0 --proxy socks5 --addr "$PROXY_IP:$PROXY_PORT"
```

Note that if you paste these commands into a shell script, which you then run with `sudo`, you might want to replace
`$USER` with `$SUDO_USER`.

For DNS to work, you might need an additional tool like [dnsproxy](https://github.com/AdguardTeam/dnsproxy) that is
configured to listen on a local UDP port and communicates with the upstream DNS server via TCP.

When you end the running of this program and want to eliminate the impact caused by the above several commands,
you can execute the following commands.
```shell
sudo ip route del 0.0.0.0/1 dev tun0
sudo ip route del 128.0.0.0/1 dev tun0
sudo ip link set tun0 down
sudo ip tuntap del tun0 mode tun
```

## CLI
```
Tunnel interface to proxy.

Usage: tun2proxy --tun <name> --proxy <type> --addr <ip:port>

Options:
  -t, --tun <name>      Name of the tun interface
  -p, --proxy <type>    What proxy type to run [possible values: socks5, http]
  -a, --addr <ip:port>  Server address with format ip:port
  -h, --help            Print help (see more with '--help')
  -V, --version         Print version
```

## TODO
- Authentication for SOCKS (plain) and HTTP (base64)
- UDP support for SOCKS
- Virtual DNS
