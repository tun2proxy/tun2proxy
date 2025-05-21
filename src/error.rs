#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("std::ffi::NulError {0:?}")]
    Nul(#[from] std::ffi::NulError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[cfg(unix)]
    #[error("nix::errno::Errno {0:?}")]
    NixErrno(#[from] nix::errno::Errno),

    #[error("TryFromIntError {0:?}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("std::net::AddrParseError {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("std::str::Utf8Error {0:?}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("TryFromSliceError {0:?}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error("IpStackError {0:?}")]
    IpStack(#[from] Box<ipstack::IpStackError>),

    #[error("DnsProtoError {0:?}")]
    DnsProto(#[from] hickory_proto::ProtoError),

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

impl From<ipstack::IpStackError> for Error {
    fn from(err: ipstack::IpStackError) -> Self {
        Self::IpStack(Box::new(err))
    }
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
            _ => std::io::Error::other(err),
        }
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub type Result<T, E = Error> = std::result::Result<T, E>;
