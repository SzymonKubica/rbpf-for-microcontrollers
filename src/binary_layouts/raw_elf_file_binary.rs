use crate::ebpf::{self, Insn};
use alloc::collections::BTreeMap;
use stdlib::{Error, ErrorKind};

use super::{CallInstructionHandler, SectionAccessor, LddwdrInstructionHandler};

/// Responsible for parsing binaries that are raw ELF files that have been stripped
/// off the debug information and that have already been processed by resolving
/// relocations.
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

impl LddwdrInstructionHandler for RawElfFileBinary<'_> {}
