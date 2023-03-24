#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("std::io::Error {0}")]
    IoError(#[from] std::io::Error),

    #[error("std::net::AddrParseError {0}")]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("smoltcp::iface::RouteTableFull {0:?}")]
    RouteTableFull(#[from] smoltcp::iface::RouteTableFull),

    #[error("smoltcp::socket::tcp::RecvError {0:?}")]
    RecvError(#[from] smoltcp::socket::tcp::RecvError),

    #[error("smoltcp::socket::tcp::ListenError {0:?}")]
    ListenError(#[from] smoltcp::socket::tcp::ListenError),

    #[error("smoltcp::socket::udp::BindError {0:?}")]
    BindError(#[from] smoltcp::socket::udp::BindError),

    #[error("smoltcp::socket::tcp::SendError {0:?}")]
    SendError(#[from] smoltcp::socket::tcp::SendError),

    #[error("&str {0}")]
    Str(String),

    #[error("String {0}")]
    String(String),

    #[error("&String {0}")]
    RefString(String),
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self::Str(err.to_string())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self::String(err)
    }
}

impl From<&String> for Error {
    fn from(err: &String) -> Self {
        Self::RefString(err.to_string())
    }
}
