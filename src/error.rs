use thiserror::Error;

#[derive(Error,Debug)]
pub enum VailError{
    #[error("Failed to parse cipher data from disk: {0}")]
    PostCardError(#[from] postcard::Error),
    #[error("Io error: {0}")]
    IoError(#[from] std::io::Error)
}
pub type Result<T> = std::result::Result<T,VailError>;
