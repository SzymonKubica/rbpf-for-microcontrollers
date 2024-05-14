use log::debug;

use crate::ebpf::{self, Insn};

use super::{
    common::ElfSection, Binary, CallInstructionHandler, LddwdrInstructionHandler, SectionAccessor,
};
use alloc::vec::Vec;
use stdlib::{Error, ErrorKind};

/// Extended version of the metadata header used by Femto-Containers. This one
/// contains information regarding the relocated calls (for supporting non-inlined,
/// non-pc-relative function calls) and the allowed helper functions. The number
/// of allowed helpers isn't included in the header as the layout appends a list
/// of all allowed helper indices at the very end of the binary, so in order to
/// recover that information we find the end of last section and read the
/// remainder of the program slice treating those bytes as the indices of the
/// allowed helper functions.
#[derive(Copy, Clone, Debug)]
struct ExtendedBytecodeHeader {
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
    functions: u32,
    /// Number of relocated function calls in the program
    relocated_calls: u32,
}

#[derive(Copy, Clone, Debug)]
struct FunctionRelocation {
    instruction_offset: u32,
    function_text_offset: u32,
}

pub struct ExtendedHeaderBinary {
    text_section: ElfSection,
    data_section: ElfSection,
    rodata_section: ElfSection,
    prog_len: usize,
    relocated_calls: Vec<FunctionRelocation>,
    allowed_helpers: Vec<u8>,
}

/// This is added for backwards compatibility with Femto-Containers. Their `gen-rbf`
/// inserts struct containing metadata regarding function offset and the offset
/// of its name in the symbol table. However, this information is nowhere used
/// in their implementation of the VM.
static FUNCTION_STRUCT_SIZE: u32 = 6;
static RELOCATED_CALL_STRUCT_SIZE: u32 = core::mem::size_of::<FunctionRelocation>() as u32;

impl ExtendedHeaderBinary {
    pub fn new(prog: &[u8]) -> ExtendedHeaderBinary {
        let header_size = core::mem::size_of::<ExtendedBytecodeHeader>() as u32;
        unsafe {
            let header = prog.as_ptr() as *const ExtendedBytecodeHeader;

            debug!("Header: \n{:?}", *header);

            let text_offset = header_size + (*header).data_len + (*header).rodata_len;
            let data_offset = header_size;
            let rodata_offset = header_size + (*header).data_len;
            let function_relocations_offset = header_size
                + (*header).data_len
                + (*header).rodata_len
                + (*header).text_len
                + (*header).functions * FUNCTION_STRUCT_SIZE;

            let allowed_helpers_offset: u32 = function_relocations_offset
                + (*header).relocated_calls * RELOCATED_CALL_STRUCT_SIZE;

            let mut relocated_calls = Vec::new();
            let function_relocations_data =
                &prog[function_relocations_offset as usize..allowed_helpers_offset as usize];
            debug!(
                "Processing {} relocated calls...",
                function_relocations_data.len() / 8
            );
            for i in 0..(function_relocations_data.len() / 8) {
                // Each of the relocation structs is 8 bytes long
                let reloc = function_relocations_data[i * 8 as usize..(i * 8 + 8) as usize].as_ptr()
                    as *const FunctionRelocation;
                debug!("Relocation call found: {:?}", *reloc);
                relocated_calls.push(*reloc.clone())
            }

            let mut allowed_helpers = Vec::new();
            for byte in &prog[allowed_helpers_offset as usize..] {
                allowed_helpers.push(*byte);
            }
            debug!("Allowed helpers: {:?}", allowed_helpers);

            return ExtendedHeaderBinary {
                text_section: ElfSection::new(text_offset, (*header).text_len),
                data_section: ElfSection::new(data_offset, (*header).data_len),
                rodata_section: ElfSection::new(rodata_offset, (*header).rodata_len),
                prog_len: (*header).text_len as usize,
                relocated_calls,
                allowed_helpers,
            };
        }
    }
}

impl SectionAccessor for ExtendedHeaderBinary {
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

impl CallInstructionHandler for ExtendedHeaderBinary {
    fn handle_call_instruction(
        &self,
        program: &[u8],
        insn_ptr: &mut usize,
        insn: crate::ebpf::Insn,
        reg: &mut [u64],
        helpers: &alloc::collections::BTreeMap<u32, crate::ebpf::Helper>,
        return_address_stack: &mut Vec<usize>,
    ) -> Result<(), Error> {
        match insn.src {
            0 => {
                // First we check if we have a custom relocation at this instruction
                if let Some(reloc) = self
                    .relocated_calls
                    .iter()
                    .find(|r| r.instruction_offset / 8 == *insn_ptr as u32 - 1)
                {
                    // If we call a helper function we push the next instruction
                    // into the return address stack and set the instruction
                    // pointer to wherever the function lives
                    return_address_stack.push(*insn_ptr);

                    *insn_ptr = (reloc.function_text_offset / 8) as usize;
                // Then we inspect if the immediate indicates a helper function
                } else if let Some(function) = helpers.get(&(insn.imm as u32)) {
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

impl LddwdrInstructionHandler for ExtendedHeaderBinary {
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
impl Binary for ExtendedHeaderBinary {}
