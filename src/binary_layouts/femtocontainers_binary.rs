use crate::lib::*;
use log::debug;

use crate::ebpf::{self, InsnLike};

use super::{Binary, CallInstructionHandler, SectionAccessor};

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

impl core::fmt::Display for FcBytecodeHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Magic: {:#x}, Version: {:#x}, Flags: {:#x}, Data Length: {:#x}, Rodata Length: {:#x}, Text Length: {:#x}, Functions Length: {:#x}",
            self.magic, self.version, self.flags, self.data_len, self.rodata_len, self.text_len, self.functions_len
        )
    }
}

/// Allows for parsing out the headers of the eBPF binaries that follow the
/// Femto-Containers custom binary layout. This layout consists of a header [`FcBytecodeHeader`]
/// containing information about the sections and their lengths present in the
/// binary, followed by the bytes of the sections without any relocation information.
pub struct FemtoContainersBinary {
    text_section: (usize, usize),
    data_section: (usize, usize),
    rodata_section: (usize, usize),
    prog_len: usize,
}

impl core::fmt::Display for FemtoContainersBinary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "FemtoContainersBinary:
             Text Section: (offset: {:#x}, len: {:#x})
             Data Section: (offset: {:#x}, len: {:#x})
             Rodata Section: (offset: {:#x}, len: {:#x})
             Program Length: {:#x}",
            self.text_section.0,
            self.text_section.1,
            self.data_section.0,
            self.data_section.1,
            self.rodata_section.0,
            self.rodata_section.1,
            self.prog_len
        )
    }
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
                text_section: (text_offset as usize, (*header).text_len as usize),
                data_section: (data_offset as usize, (*header).data_len as usize),
                rodata_section: (rodata_offset as usize, (*header).rodata_len as usize),
                prog_len: (*header).text_len as usize,
            };

            debug!(
                "Successufully parsed the FemtoContainersBinary: \n{}",
                program
            );

            program
        }
    }
}

impl SectionAccessor for FemtoContainersBinary {
    #[inline(always)]
    fn get_text_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error> {
        Ok(&program[self.text_section.0..(self.text_section.0 + self.text_section.1)])
    }
    #[inline(always)]
    fn get_data_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error> {
        Ok(&program[self.data_section.0..(self.data_section.0 + self.data_section.1)])
    }
    #[inline(always)]
    fn get_rodata_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error> {
        Ok(&program[self.rodata_section.0..(self.rodata_section.0 + self.rodata_section.1)])
    }
}

impl CallInstructionHandler for FemtoContainersBinary {
    fn handle_call_instruction(
        &self,
        _program: &[u8],
        insn_ptr: &mut usize,
        insn: &dyn InsnLike,
        reg: &mut [u64],
        helpers: &alloc::collections::BTreeMap<u32, ebpf::Helper>,
        return_address_stack: &mut Vec<usize>,
        insn_ptr_step_size: usize,
    ) -> Result<(), Error> {
        match insn.src() {
            0 => {
                if let Some(function) = helpers.get(&(insn.imm() as u32)) {
                    reg[0] = function(reg[1], reg[2], reg[3], reg[4], reg[5]);
                } else {
                    Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Error: unknown helper function (id: {:#x})",
                            insn.imm() as u32
                        ),
                    ))?;
                }
            }
            1 => {
                // Here the source register 1 indicates that we are making
                // a call relative to the current instruction pointer
                return_address_stack.push(*insn_ptr);
                *insn_ptr =
                    ((*insn_ptr as i32 + insn.imm() * insn_ptr_step_size as i32) as usize) as usize;
            }
            _ => {
                Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "Error: invalid CALL src register value: (src: {})",
                        insn.src() as u32
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
        _program: &[u8],
        _insn: &dyn InsnLike,
        _next_insn: &dyn InsnLike,
        _dst: usize,
        _insn_ptr: &mut usize,
        _reg: &mut [u64],
    ) -> Result<(), Error> {
        return Err(Error::new(
            ErrorKind::Other,
            "LDDWD instruction not supported in this binary layout",
        ));
    }
    fn handle_lddwr_instruction(
        &self,
        _program: &[u8],
        _insn: &dyn InsnLike,
        _next_insn: &dyn InsnLike,
        _dst: usize,
        _insn_ptr: &mut usize,
        _reg: &mut [u64],
    ) -> Result<(), Error> {
        return Err(Error::new(
            ErrorKind::Other,
            "LDDWR instruction not supported in this binary layout",
        ));
    }
}

impl LddwdrInstructionHandler for FemtoContainersBinary {
    #[inline(always)]
    fn handle_lddwd_instruction(
        &self,
        program: &[u8],
        insn: &dyn InsnLike,
        next_insn: &dyn InsnLike,
        dst: usize,
        insn_ptr: &mut usize,
        reg: &mut [u64],
    ) -> Result<(), Error> {
        *insn_ptr += ebpf::INSN_SIZE;
        reg[dst] = program.as_ptr() as u64
            + self.data_section.0 as u64
            + ((insn.imm() as u32) as u64)
            + ((next_insn.imm() as u64) << 32);

        Ok(())
    }

    #[inline(always)]
    fn handle_lddwr_instruction(
        &self,
        program: &[u8],
        insn: &dyn InsnLike,
        next_insn: &dyn InsnLike,
        dst: usize,
        insn_ptr: &mut usize,
        reg: &mut [u64],
    ) -> Result<(), Error> {
        *insn_ptr += ebpf::INSN_SIZE;
        reg[dst] = program.as_ptr() as u64
            + self.rodata_section.0 as u64
            + ((insn.imm() as u32) as u64)
            + ((next_insn.imm() as u64) << 32);
        Ok(())
    }
}

impl Binary for FemtoContainersBinary {}
