use log::debug;
use stdlib::collections::Vec;
use stdlib::{Error, ErrorKind};

use crate::ebpf::{self, Insn};

use super::common::ElfSection;
use super::{CallInstructionHandler, SectionAccessor, Binary};

/// Header present at the start of the Femto-Containers binary.
#[derive(Copy, Clone, Debug)]
struct FcBytecodeHeader {
    /// Magic number
    magic: u32,
    /// Version of the application
    version: u32,
    flags: u32,
    /// Length of the data section
    data_len: u32,
    /// Length of the rodata section
    rodata_len: u32,
    /// Length of the text section
    text_len: u32,
    /// Number of functions available
    functions_len: u32,
}

/// Allows for parsing out the headers of the eBPF binaries that follow the
/// Femto-Containers custom binary layout. This layout consists of a header [`FcBytecodeHeader`]
/// containing information about the sections and their lengths present in the
/// binary, followed by the bytes of the sections without any relocation information.
pub struct FemtoContainersBinary {
    text_section: ElfSection,
    data_section: ElfSection,
    rodata_section: ElfSection,
    prog_len: usize,
}

impl FemtoContainersBinary {
    pub fn new(prog: &[u8]) -> Self {
        let header_size = core::mem::size_of::<FcBytecodeHeader>() as u32;
        unsafe {
            let header = prog.as_ptr() as *const FcBytecodeHeader;

            debug!("Bytecode Header: \n{:?}", *header);

            let data_offset = header_size;
            let rodata_offset = data_offset + (*header).data_len;
            let text_offset = rodata_offset + (*header).rodata_len;

            let program = FemtoContainersBinary {
                text_section: ElfSection::new(text_offset, (*header).text_len),
                data_section: ElfSection::new(data_offset, (*header).data_len),
                rodata_section: ElfSection::new(rodata_offset, (*header).rodata_len),
                prog_len: (*header).text_len as usize,
            };

            program
        }
    }
}

impl SectionAccessor for FemtoContainersBinary {
    fn get_text_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error> {
        Ok(self.text_section.extract_section_reference(program))
    }
    fn get_data_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error> {
        Ok(self.data_section.extract_section_reference(program))
    }
    fn get_rodata_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error> {
        Ok(self.rodata_section.extract_section_reference(program))
    }
}

impl CallInstructionHandler for FemtoContainersBinary {
    fn handle_call_instruction(
        &self,
        program: &[u8],
        insn_ptr: &mut usize,
        insn: Insn,
        reg: &mut [u64],
        helpers: &alloc::collections::BTreeMap<u32, ebpf::Helper>,
        return_address_stack: &mut Vec<usize>,
    ) -> Result<(), Error> {
        match insn.src {
            0 => {
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
            _ => {
                Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "Error: invalid CALL src register value: (src: {})",
                        insn.src as u32
                    ),
                ))?;
            }
        }
        Ok(())
    }
}

/// Femto-Containers and my custom extended header layout contain custom instructions
/// (not present in the original eBPF ISA) which allow for executing load instructions
/// from the .data / .rodata sections by using an offset from the
/// start of the section as the immediate operand in the instruction.
///
/// Thanks to this architecture, there is no need for .data / .rodata relocation
/// resolution as the bytecode header contains all necessary infromation (header
/// length and lengths of the sections) so that we can perform a memory access
/// relative to the entire program buffer and read from .data / .rodata sections.
///
/// This trait needs to be implemented by all binary layouts that allow for handling
/// those kinds of special instructions and is used by the generic interpreter
/// to handle those. The default impelementation returns an error because by
/// default the binaries shouldn't contain those custom instructions.
pub trait LddwdrInstructionHandler {
    fn handle_lddwd_instruction(
        &self,
        program: &[u8],
        insn: Insn,
        dst: usize,
        insn_ptr: &mut usize,
        text_section: &[u8],
        reg: &mut [u64],
    ) -> Result<(), Error> {
        return Err(Error::new(
            ErrorKind::Other,
            "LDDWD instruction not supported in this binary layout",
        ));
    }
    fn handle_lddwr_instruction(
        &self,
        program: &[u8],
        insn: Insn,
        dst: usize,
        insn_ptr: &mut usize,
        text_section: &[u8],
        reg: &mut [u64],
    ) -> Result<(), Error> {
        return Err(Error::new(
            ErrorKind::Other,
            "LDDWR instruction not supported in this binary layout",
        ));
    }
}

impl LddwdrInstructionHandler for FemtoContainersBinary {
    fn handle_lddwd_instruction(
        &self,
        program: &[u8],
        insn: Insn,
        dst: usize,
        insn_ptr: &mut usize,
        text_section: &[u8],
        reg: &mut [u64],
    ) -> Result<(), Error> {
        let next_insn = ebpf::get_insn(text_section, *insn_ptr);
        *insn_ptr += 1;
        reg[dst] = program.as_ptr() as u64
            + self.data_section.offset as u64
            + ((insn.imm as u32) as u64)
            + ((next_insn.imm as u64) << 32);

        Ok(())
    }

    fn handle_lddwr_instruction(
        &self,
        program: &[u8],
        insn: Insn,
        dst: usize,
        insn_ptr: &mut usize,
        text_section: &[u8],
        reg: &mut [u64],
    ) -> Result<(), Error> {
        let next_insn = ebpf::get_insn(text_section, *insn_ptr);
        *insn_ptr += 1;
        reg[dst] = program.as_ptr() as u64
            + self.rodata_section.offset as u64
            + ((insn.imm as u32) as u64)
            + ((next_insn.imm as u64) << 32);
        Ok(())
    }
}

impl Binary for FemtoContainersBinary {}
