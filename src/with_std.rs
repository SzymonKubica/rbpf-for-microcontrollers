pub mod with_std {
    pub use std::u32;
    pub use std::u64;
    pub use std::string::String;
    pub use std::string::ToString;
    pub use std::println;
    pub use std::io::{Error, ErrorKind};
    pub mod collections {
        pub use std::collections::{HashMap, HashSet};
        pub use std::vec::Vec;
    }
}

