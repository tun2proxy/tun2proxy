# Changelog for Tun2Proxy

## 0.1.1

- Updated dependencies:
  - `chrono`: v0.4, ready for next planned release ;
  - `clap`: last version ;
  - `mio`: v0.8 + rename renamed feature (os-util became os-ext) + some fixes due to removal of `TcpSocket` type ;
  - `smoltcp`: set v0.8 but from crates.io, plus old reference could not work.
- Fixes:
  - Removed typo from Cargo.toml ;
  - Clippy.
