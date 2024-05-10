//! This module defines the three different supported layouts of the eBPF
//! bytecode files that can be processed by the vm:
//! - only `.text` section - the VM only executes the instructions present
//!   directly in that section and cannot access `.data` or `.rodata` or call
//!   non-pc relative, non-inlined functions.
//! - using Femto-Containers header - the eBPF binary has the custom format first
//!   introduced by Femto-Containers (link
//!   here)[https://github.com/future-proof-iot/middleware2022-femtocontainers/tree/main]
//! - using a custom extended header containing function call relocations for
//!   non-inlined, non-pc-relative function calls and specifying allowed helper
//!   functions.
//! - using a raw ELF file and performing relocations before execution based
//!   on the relocation information specified in the binary.
//!
//! In order to avoid duplicating the interpreter to support all of these different
//! layouts, I introduced a new version of the interpreter which uses the
//! strategy pattern to change the behaviour of the interpreter based on the
//! binary layout that it is operating on. The two main things that need to change
//! are:
//! - accessing instructions from `.text` section. Different layouts have header
//!   sections that change the offset at which the first executable instruction is
//!   located in the loaded program buffer.
//! - handling funtion calls and load/store instruction is layout specific

use crate::ebpf::{self, Insn};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use stdlib::Error;

mod raw_elf_file_binary;
pub use self::raw_elf_file_binary::RawElfFileBinary;

mod femtocontainers_binary;
pub use self::femtocontainers_binary::{FemtoContainersBinary, LddwdrInstructionHandler};

mod common;
mod extended_header_binary;
pub use self::extended_header_binary::ExtendedHeaderBinary;

pub trait Binary: SectionAccessor + CallInstructionHandler + LddwdrInstructionHandler {}

/// Implementations of this trait should provide access to the different sections
/// of the eBPF binary file. The idea is that the structs that we implement
/// for defining behaviour for different binary layouts listed above implement
/// and can be swapped in and out in the generic interpreter.
pub trait SectionAccessor {
    fn get_text_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error>;
    fn get_data_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error>;
    fn get_rodata_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error>;
}

/// Different binary layouts deal differently with function calls. For instance,
/// the raw ELF file layout requires relocations to be performed before execution,
/// but then it does support non-inlined, non-pc-relative function calls.
/// The extended interpreter has a list of relocated calls and performs a lookup
/// there to see if the call relocation can be resolved. Femto-Containers layout
/// only supports helper function calls and pc-relative static function calls.
pub trait CallInstructionHandler {
    fn handle_call_instruction(
        &self,
        program: &[u8],
        insn_ptr: &mut usize,
        insn: Insn,
        reg: &mut [u64],
        helpers: &BTreeMap<u32, ebpf::Helper>,
        return_address_stack: &mut Vec<usize>,
    ) -> Result<(), Error>;
}

