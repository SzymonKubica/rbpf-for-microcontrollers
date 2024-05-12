use stdlib::collections::Vec;
use stdlib::{Error, ErrorKind};

use crate::ebpf::{self, Insn};

use super::{Binary, CallInstructionHandler, SectionAccessor, LddwdrInstructionHandler};

pub struct TextSectionOnlyBinary {}

impl SectionAccessor for TextSectionOnlyBinary {
    fn get_text_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error> {
        Ok(program)
    }
    fn get_data_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error> {
        Err(Error::new(
            ErrorKind::Other,
            "Error: data section not present in this binary layout",
        ))
    }
    fn get_rodata_section<'a>(&self, program: &'a [u8]) -> Result<&'a [u8], Error> {
        Err(Error::new(
            ErrorKind::Other,
            "Error: rodata section not present in this binary layout",
        ))
    }
}

impl CallInstructionHandler for TextSectionOnlyBinary {
    fn handle_call_instruction(
        &self,
        program: &[u8],
        insn_ptr: &mut usize,
        insn: Insn,
        reg: &mut [u64],
        helpers: &alloc::collections::BTreeMap<u32, ebpf::Helper>,
        return_address_stack: &mut Vec<usize>,
    ) -> Result<(), Error> {
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
        Ok(())
    }
}

impl LddwdrInstructionHandler for TextSectionOnlyBinary {}
impl Binary for TextSectionOnlyBinary {}
