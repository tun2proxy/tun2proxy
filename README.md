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
```
# Create a tunnel interface named tun0 which your user can bind to.
sudo ip tuntap add name tun0 mode tun user $USER
sudo ip link set tun0 up

# To prevent a loop, replace 1.2.3.4 with the IP address of the proxy server.
# This will add a route to the proxy server that behaves like the default route.
sudo ip route add 1.2.3.4 $(ip route | grep '^default' | cut -d' ' -f2-)

# Route all your traffic through tun0 without interfering with the default route.
sudo ip route add 128.0.0.0/1 dev tun0
sudo ip route add 0.0.0.0/1 dev tun0

# Again, replace 1.2.3.4 with the IP address of the proxy server.
./target/release/tun2proxy --tun tun0 --socks5 1.2.3.4
```

Note that if you paste these commands into a shell script, which you then run with `sudo`, you might want to replace
`$USER` with `$SUDO_USER`.

## CLI
```
tun2proxy 0.1.0
Tunnel interface to proxy.

USAGE:
    tun2proxy [OPTIONS] --tun <TUN>

FLAGS:
        --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -h, --http <IP:PORT>      HTTP server to use
    -s, --socks5 <IP:PORT>    SOCKS5 server to use
    -t, --tun <TUN>           Name of the tun interface
```