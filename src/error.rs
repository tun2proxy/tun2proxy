#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("std::ffi::NulError {0:?}")]
    Nul(#[from] std::ffi::NulError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("TryFromIntError {0:?}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("std::net::AddrParseError {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("std::str::Utf8Error {0:?}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("TryFromSliceError {0:?}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error("IpStackError {0:?}")]
    IpStack(#[from] ipstack::IpStackError),

    #[error("DnsProtoError {0:?}")]
    DnsProto(#[from] trust_dns_proto::error::ProtoError),

    #[error("httparse::Error {0:?}")]
    Httparse(#[from] httparse::Error),

    #[error("digest_auth::Error {0:?}")]
    DigestAuth(#[from] digest_auth::Error),

    #[cfg(target_os = "android")]
    #[error("jni::errors::Error {0:?}")]
    Jni(#[from] jni::errors::Error),

    #[error("{0}")]
    String(String),

    #[error("std::num::ParseIntError {0:?}")]
    IntParseError(#[from] std::num::ParseIntError),
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self::String(err.to_string())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self::String(err)
    }
}

impl From<&String> for Error {
    fn from(err: &String) -> Self {
        Self::String(err.to_string())
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Io(err) => err,
            _ => std::io::Error::new(std::io::ErrorKind::Other, err),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
