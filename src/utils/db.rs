use crate::data::error::Error;

pub trait StanderizeError<V> {
    fn warn_err(self) -> Result<V, Error>;
    fn debug_err(self) -> Result<V, Error>;
}

impl<V, E> StanderizeError<V> for Result<V, E>
where
    E: std::error::Error,
{
    fn warn_err(self) -> Result<V, Error> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => {
                tracing::warn!("{}", e);
                Err(Error::InternalServerError)
            }
        }
    }

    fn debug_err(self) -> Result<V, Error> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => {
                tracing::debug!("{}", e);
                Err(Error::InternalServerError)
            }
        }
    }
}
