pub mod without_std {
    use alloc::string::String;
    pub use core::u32;
    pub use core::u64;
    pub use core::f64;
    //pub use libc_print::std_name::{println, eprintln, dbg};

    // Dummy implementation of Error for no std.
    #[derive(Debug)]
    pub struct Error {
        kind: ErrorKind,
        error: String,
    }

    impl Error {
        pub fn new<S : Into<String>>(kind: ErrorKind, error: S) -> Error {
            Error { kind, error: error.into() }
        }
    }


    #[derive(Debug)]
    pub enum ErrorKind {
        Other,
    }
}
