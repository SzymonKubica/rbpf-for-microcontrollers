use crate::thumb_16bit_encoding::Emittable;
use crate::{jit_thumbv7em::emit, JitMemory};
use log::debug;
use stdlib::collections::Vec;
use stdlib::{Error, ErrorKind, String};
/// 32-bit Thumb encoding for instructions that have two registers
pub struct Immediate8TwoRegistersLongEncoding {
    opcode: u16,
    rn: u8,
    rt: u8,
    p: u8,
    u: u8,
    w: u8,
    imm8: u8,
}

impl Immediate8TwoRegistersLongEncoding {
    pub fn new(
        opcode: u16,
        rn: u8,
        rt: u8,
        p: u8,
        u: u8,
        w: u8,
        imm8: u8,
    ) -> Immediate8TwoRegistersLongEncoding {
        Immediate8TwoRegistersLongEncoding {
            opcode,
            rn,
            rt,
            p,
            u,
            w,
            imm8,
        }
    }
}

impl Emittable for Immediate8TwoRegistersLongEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        // Because of the endianness of the machine (we are in Little Endian)
        // we need to encode the two words in reverse order.
        encoding |= (self.rt as u32 & 0b1111) << 12;
        encoding |= 0b1 << 11;
        encoding |= (self.p as u32 & 0b1) << 10;
        encoding |= (self.u as u32 & 0b1) << 9;
        encoding |= (self.w as u32 & 0b1) << 8;
        encoding |= self.imm8 as u32 & 0b11111111;

        encoding <<= 16;
        encoding |= (self.opcode as u32) << 4;
        encoding |= self.rn as u32 & 0b1111;
        debug!("Encoding: {:#x}", encoding);
        emit::<u32>(mem, encoding);
        Ok(())
    }
}
