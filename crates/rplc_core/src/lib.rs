mod config;
mod diagnostics;
mod generator;
mod validator;

pub use config::{Config, ConfigOrArray};
pub use diagnostics::{Severity, ValidationCode};
pub use generator::{GenerateError, MultiGenerateError, generate, generate_multiple};
pub use validator::{validate, validate_multiple};
