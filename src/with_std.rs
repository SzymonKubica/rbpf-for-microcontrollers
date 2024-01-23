pub mod with_std {
    pub use std::u32;
    pub use std::io::{Error, ErrorKind};
    pub mod collections {
        pub use std::collections::{HashMap, HashSet};
    }
}

