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
use stdlib::{Error, ErrorKind};

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

pub struct RawElfFileBinary<'a> {
    /// The parsed ELF binary used for looking up bytecode sections
    binary: goblin::elf::Elf<'a>,
}

impl<'a> RawElfFileBinary<'a> {
    pub fn new(program: &'a [u8]) -> Result<RawElfFileBinary<'a>, Error> {
        let Ok(binary) = goblin::elf::Elf::parse(program) else {
            Err(Error::new(ErrorKind::Other, "Failed to parse ELF binary"))?
        };
        Ok(Self { binary })
    }
    fn extract_section<'b>(
        &self,
        section_name: &'static str,
        program: &'b [u8],
    ) -> Result<&'b [u8], Error> {
        for section in &self.binary.section_headers {
            if let Some(name) = self.binary.shdr_strtab.get_at(section.sh_name) {
                if name == section_name {
                    let section_start = section.sh_offset as usize;
                    let section_end = (section.sh_offset + section.sh_size) as usize;
                    return Ok(&program[section_start..section_end]);
                }
            }
        }
        Err(Error::new(
            ErrorKind::Other,
            format!("Section {} not found.", section_name),
        ))
    }
}

impl<'a> SectionAccessor for RawElfFileBinary<'a> {
    fn get_text_section<'b>(&self, program: &'b [u8]) -> Result<&'b [u8], Error> {
        self.extract_section(".text", &program)
    }
    fn get_data_section<'b>(&self, program: &'b [u8]) -> Result<&'b [u8], Error> {
        self.extract_section(".data", &program)
    }
    fn get_rodata_section<'b>(&self, program: &'b [u8]) -> Result<&'b [u8], Error> {
        self.extract_section(".rodata", &program)
    }
}

impl CallInstructionHandler for RawElfFileBinary<'_> {
    fn handle_call_instruction(
        &self,
        program: &[u8],
        insn_ptr: &mut usize,
        insn: Insn,
        reg: &mut [u64],
        helpers: &BTreeMap<u32, ebpf::Helper>,
        return_address_stack: &mut Vec<usize>,
    ) -> Result<(), Error> {
        // The source register determines if we have a helper call or a PC-relative call.
        match insn.src {
            0 => {
                // Do not delegate the check to the verifier, since registered functions can be
                // changed after the program has been verified.
                if let Some(function) = helpers.get(&(insn.imm as u32)) {
                    reg[0] = function(reg[1], reg[2], reg[3], reg[4], reg[5]);
                } else {
                    Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Error: unknown helper function (id: {:#x})",
                            insn.imm as u32
                        ),
                    ))?;
                }
            }
            1 => {
                // Here the source register 1 indicates that we are making
                // a call relative to the current instruction pointer
                return_address_stack.push(*insn_ptr);
                *insn_ptr = ((*insn_ptr as i32 + insn.imm) as usize) as usize;
            }
            3 => {
                // This is a hacky implementation of calling functions
                // using their actual memory address (not specified in the
                // eBPF standard). Those calls are denoted by value 3
                // being present in the source register. The reason we
                // need those is when we want to have non-inlined, non-static
                // functions defined inside of eBPF programs. Calls to those
                // functions aren't compiled as PC-relative calls and
                // they need manual relocation resolution

                return_address_stack.push(*insn_ptr);
                let function_address = insn.imm as u32;
                let program_address = program.as_ptr() as u32;
                let function_offset = function_address - program_address as u32;
                *insn_ptr = (function_offset / 8) as usize;
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}
