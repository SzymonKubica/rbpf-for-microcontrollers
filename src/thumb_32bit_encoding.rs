use crate::thumb_16bit_encoding::Emittable;
use crate::{jit_thumbv7em::emit, JitMemory};
use log::debug;
use stdlib::collections::Vec;
use stdlib::{Error, ErrorKind, String};

/// Base way of encoding 32-bit Thumb instructions. Instruction is layed out
/// as follows:
/// 111|__|_______|____|_|______________|
///     ^op1   ^op2     ^op
struct Thumb32BaseOpcodeEncoding {
    op1: u8,
    op2: u8,
    op: u8,
}

impl Thumb32BaseOpcodeEncoding {
    pub const fn new(op1: u8, op2: u8, op: u8) -> Thumb32BaseOpcodeEncoding {
        Thumb32BaseOpcodeEncoding {
            op1,
            op2,
            op,
        }
    }
}

type Opcode = Thumb32BaseOpcodeEncoding;


impl Thumb32BaseOpcodeEncoding {
    pub fn apply(&self, encoding: &mut u32) {
        *encoding |= 0b111 << 29;
        *encoding |= (self.op1 as u32 & 0b11) << 27;
        *encoding |= (self.op2 as u32 & 0b1111111) << 20;
        *encoding |= (self.op as u32 & 0b1) << 14;
    }
}

pub struct Imm12TwoRegsEncoding {
    opcode: u16,
    rn: u8,
    rt: u8,
    imm12: u16,
}

impl Imm12TwoRegsEncoding {
    pub fn new(opcode: u16, rn: u8, rt: u8, imm12: u16) -> Imm12TwoRegsEncoding {
        Imm12TwoRegsEncoding {
            opcode,
            rn,
            rt,
            imm12,
        }
    }
}

impl Emittable for Imm12TwoRegsEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        // Because of the endianness of the machine (we are in Little Endian)
        // we need to encode the two words in reverse order.
        encoding |= (self.rt as u32 & 0b1111) << 12;
        encoding |= self.imm12 as u32 & 0b111111111111;
        encoding <<= 16;
        encoding |= (self.opcode as u32) << 4;
        encoding |= self.rn as u32 & 0b1111;
        emit::<u32>(mem, encoding);
        Ok(())
    }
}


/// 32-bit Thumb encoding for instructions that have two registers
pub struct Imm8TwoRegsEncoding {
    opcode: u16,
    rn: u8,
    rt: u8,
    p: u8,
    u: u8,
    w: u8,
    imm8: u8,
}

impl Imm8TwoRegsEncoding {
    pub fn new(opcode: u16, rn: u8, rt: u8, p: u8, u: u8, w: u8, imm8: u8) -> Imm8TwoRegsEncoding {
        Imm8TwoRegsEncoding {
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

impl Emittable for Imm8TwoRegsEncoding {
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
        emit::<u32>(mem, encoding);
        Ok(())
    }
}


