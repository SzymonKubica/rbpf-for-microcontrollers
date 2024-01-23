#[macro_use]
extern crate alloc;
extern crate hashbrown;

pub mod with_alloc {
    pub use alloc::{boxed, string, vec};
    pub use alloc::string::String;
    pub use alloc::string::ToString;

    pub mod collections {
        pub use hashbrown::{HashSet, HashMap};
        pub use alloc::vec::Vec;
    }
}
