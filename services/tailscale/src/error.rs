use std::error::Error as StdError;
use std::fmt;
use std::process::Output;

/// Error type for tailscale operations
#[derive(Debug)]
pub enum TailscaleError {
    /// API request failed
    Api {
        /// The underlying error that caused the API failure
        source: Box<dyn StdError + Send + Sync>,
        /// Context describing what operation failed
        context: String,
    },

    /// Command execution failed
    Command {
        /// The command that was executed
        command: String,
        /// Optional output from the failed command
        output: Option<String>,
        /// Optional source error if command failed to spawn
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Failed to parse data
    Parsing {
        /// What was being parsed (e.g., "IPv4 address")
        what: String,
        /// The input string that failed to parse
        input: String,
        /// Optional underlying parsing error
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Data conversion error (UTF-8, path conversion, etc.)
    Conversion {
        /// What was being converted
        what: String,
        /// Optional underlying conversion error
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Generic error with context
    Other {
        /// Error message
        message: String,
        /// Optional underlying error
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

impl TailscaleError {
    /// Create an API error
    pub fn api(
        source: impl Into<Box<dyn StdError + Send + Sync>>,
        context: impl Into<String>,
    ) -> Self {
        Self::Api {
            source: source.into(),
            context: context.into(),
        }
    }

    /// Create a command execution error
    pub fn command(command: impl Into<String>, output: Option<Output>) -> Self {
        Self::Command {
            command: command.into(),
            output: output.map(|o| format!("{:?}", o)),
            source: None,
        }
    }

    /// Create a command spawn error
    pub fn command_spawn(
        command: impl Into<String>,
        source: impl Into<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self::Command {
            command: command.into(),
            output: None,
            source: Some(source.into()),
        }
    }

    /// Create a parsing error
    pub fn parsing(what: impl Into<String>, input: impl Into<String>) -> Self {
        Self::Parsing {
            what: what.into(),
            input: input.into(),
            source: None,
        }
    }

    /// Create a parsing error with source
    pub fn parsing_with_source(
        what: impl Into<String>,
        input: impl Into<String>,
        source: impl Into<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self::Parsing {
            what: what.into(),
            input: input.into(),
            source: Some(source.into()),
        }
    }

    /// Create a conversion error
    pub fn conversion(what: impl Into<String>) -> Self {
        Self::Conversion {
            what: what.into(),
            source: None,
        }
    }

    /// Create a conversion error with source
    pub fn conversion_with_source(
        what: impl Into<String>,
        source: impl Into<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self::Conversion {
            what: what.into(),
            source: Some(source.into()),
        }
    }

    /// Create a generic error
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other {
            message: message.into(),
            source: None,
        }
    }

    /// Create a generic error with source
    pub fn other_with_source(
        message: impl Into<String>,
        source: impl Into<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self::Other {
            message: message.into(),
            source: Some(source.into()),
        }
    }
}

impl fmt::Display for TailscaleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api { context, .. } => write!(f, "Tailscale API error: {}", context),
            Self::Command {
                command, output, ..
            } => {
                if let Some(output) = output {
                    write!(f, "Command '{}' failed: {}", command, output)
                } else {
                    write!(f, "Command '{}' failed", command)
                }
            }
            Self::Parsing { what, input, .. } => {
                write!(f, "Failed to parse {} from '{}'", what, input)
            }
            Self::Conversion { what, .. } => {
                write!(f, "Failed to convert {}", what)
            }
            Self::Other { message, .. } => write!(f, "{}", message),
        }
    }
}

impl StdError for TailscaleError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Api { source, .. } => Some(source.as_ref() as &(dyn StdError + 'static)),
            Self::Command { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &(dyn StdError + 'static)),
            Self::Parsing { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &(dyn StdError + 'static)),
            Self::Conversion { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &(dyn StdError + 'static)),
            Self::Other { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &(dyn StdError + 'static)),
        }
    }
}

// Conversion from TailscaleAPIError for backward compatibility
impl From<crate::client::TailscaleAPIError> for TailscaleError {
    fn from(err: crate::client::TailscaleAPIError) -> Self {
        use crate::client::TailscaleAPIError;
        match err {
            TailscaleAPIError::RequestError(e) => Self::api(
                std::io::Error::new(std::io::ErrorKind::Other, e),
                "request failed",
            ),
            TailscaleAPIError::BodyError(e) => Self::api(e, "response body error"),
        }
    }
}
