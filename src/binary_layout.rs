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

use crate::ebpf::Insn;
use stdlib::{Error, ErrorKind};

/// Implementations of this trait should provide access to the different sections
/// of the eBPF binary file. The idea is that the structs that we implement
/// for defining behaviour for different binary layouts listed above implement
/// and can be swapped in and out in the generic interpreter.
pub trait SectionAccessor<'a> {
    fn get_text_section(&'a self) -> Result<&'a [u8], Error>;
    fn get_data_section(&'a self) -> Result<&'a [u8], Error>;
    fn get_rodata_section(&'a self) -> Result<&'a [u8], Error>;
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
        insn_ptr: usize,
        insn: Insn,
        registers: &mut [u64],
    ) -> Result<(), Error>;
}

/// When overriding the interpreter behaviour for CALL instructions, we also need
/// to override the exit, because an exit from a subroutine should jump back to
/// the call site instead of terminating the execution.
pub trait ExitInstructionHandler {
    fn handle_exit_instruction(
        &self,
        insn_ptr: usize,
        insn: Insn,
        registers: &mut [u64],
    ) -> Result<Option<u64>, Error>;
}

pub struct RawElfFileBinary<'a> {
    binary: &'a goblin::elf::Elf<'a>,
    program: &'a [u8],
}

impl<'a> RawElfFileBinary<'a> {
    fn extract_section(&self, section_name: &'static str) -> Result<&'a [u8], Error> {
        for section in &self.binary.section_headers {
            if let Some(name) = self.binary.shdr_strtab.get_at(section.sh_name) {
                if name == section_name {
                    let section_start = section.sh_offset as usize;
                    let section_end = (section.sh_offset + section.sh_size) as usize;
                    return Ok(&self.program[section_start..section_end]);
                }
            }
        }
        Err(Error::new(
            ErrorKind::Other,
            format!("Section {} not found.", section_name),
        ))
    }
}

impl<'a> SectionAccessor<'a> for RawElfFileBinary<'a> {
    fn get_text_section(&self) -> Result<&[u8], Error> {
        self.extract_section(".text")
    }
    fn get_data_section(&self) -> Result<&[u8], Error> {
        self.extract_section(".data")
    }
    fn get_rodata_section(&self) -> Result<&[u8], Error> {
        self.extract_section(".rodata")
    }
}
