/// Ensures compatibility with no_std.
pub mod without_std {
    use alloc::string::String;
    use alloc::string::ToString;
    pub use core::u32;
    pub use core::u64;

    /// Dummy implementation of Error for no std.
    /// It ensures that the existing code can use it with the same interface
    /// as the Error from std::io::Error.
    #[derive(Debug)]
    pub struct Error {
        kind: ErrorKind,
        pub error: String,
    }

    impl Error {
        /// New function added for compatibility with the existing code.
        pub fn new<S: Into<String>>(kind: ErrorKind, error: S) -> Error {
            Error {
                kind,
                error: error.into(),
            }
        }
    }

    /// The minimum set of variants to make the dummy ErrorKind work with
    /// the existing code.
    #[derive(Debug)]
    #[warn(dead_code)]
    pub enum ErrorKind {
        /// The code only uses this variant.
        Other,
    }
}
