#[macro_use]
extern crate alloc;
extern crate hashbrown;

pub mod with_alloc {
    use alloc::{boxed, string, vec};

    pub mod collections {
        pub use hashbrown::{HashSet, HashMap};
    }
}
