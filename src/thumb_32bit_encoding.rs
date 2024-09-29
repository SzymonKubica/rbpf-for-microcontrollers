// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Copyright 2024 Szymon Kubica <szymo.kubica@gmail.com>
//      (ARM thumbv7em architecture 32bit encoding implementation)

use crate::thumb_16bit_encoding::Emittable;
use crate::{jit_thumbv7em::emit, JitMemory};

use crate::lib::*;

/// Defines how to encode the opcode of 32-bit Thumb instructions.
/// Instruction is laid out as follows:
/// 111|--|-------|----|-|--------------|
/// ___ ^op1___^op2_____^op
#[derive(Debug, Clone, Copy)]
pub struct Thumb32OpcodeEncoding {
    op1: u8,
    op2: u8,
    op: u8,
}

impl Thumb32OpcodeEncoding {
    pub const fn new(op1: u8, op2: u8, op: u8) -> Thumb32OpcodeEncoding {
        Thumb32OpcodeEncoding { op1, op2, op }
    }
}

type Opcode = Thumb32OpcodeEncoding;

impl Into<u32> for Thumb32OpcodeEncoding {
    fn into(self) -> u32 {
        // We turn the encoding into a mask that is compatible with the Little
        // Endian encoding used in the other implemntations of the Emittable trait.
        // The way it works is that the most significant word of the instruction
        // is written in the lower bits and the lowest 16 bits of the actual
        // encoding are written into the 16 most significant bits. That way,
        // the opcode can be 'encrusted' into the generated encoding by simply
        // using |= (as it already has the words reordered properly)
        let mut encoding = 0;
        // first encode the lower word
        encoding |= (self.op as u32 & 0b1) << 15;
        encoding <<= 16; // We now shift the lower bits and write the higher bits
        encoding |= 0b111 << 13; // Indicates that we have a 32-bit instruction
        encoding |= (self.op1 as u32 & 0b11) << 11;
        encoding |= (self.op2 as u32 & 0b1111111) << 4;
        encoding
    }
}

pub struct Imm5LSLTwoRegsEncoding {
    opcode: Thumb32OpcodeEncoding,
    rm: u8,
    rd: u8,
    imm5: u8,
}

impl Imm5LSLTwoRegsEncoding {
    pub fn new(opcode: Opcode, rm: u8, rd: u8, imm5: u8) -> Imm5LSLTwoRegsEncoding {
        Imm5LSLTwoRegsEncoding {
            opcode,
            rm,
            rd,
            imm5,
        }
    }
}

impl Emittable for Imm5LSLTwoRegsEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {

        let mut encoding = 0;

        // We first break up the immediate into its parts
        let imm3 = (self.imm5 >> 2 & 0b111) as u32;
        let imm2 = (self.imm5 & 0b11) as u32;

        // Because of the endianness of the machine (we are in Little Endian)
        // we need to encode the two words in reverse order.

        // We first write the lower word
        encoding |= imm3 << 12;
        encoding |= (self.rd as u32 & 0b1111) << 8;
        encoding |= imm2 << 6;
        encoding |= self.rm as u32 & 0b1111;
        encoding <<= 16;
        // LSL always has the 4 bits of the higher word set.
        encoding |= 0b1111;

        // Now we get the encoded opcode and stamp it on top of the instruction
        let opcode_encoding: u32 = self.opcode.into();
        encoding |= opcode_encoding;
        emit::<u32>(mem, encoding);
        Ok(())
    }
}

pub struct Imm12TwoRegsEncoding {
    opcode: Thumb32OpcodeEncoding,
    rn: u8,
    rt: u8,
    imm12: u16,
}

impl Imm12TwoRegsEncoding {
    pub fn new(opcode: Opcode, rn: u8, rt: u8, imm12: u16) -> Imm12TwoRegsEncoding {
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

        // We first write the operands
        encoding |= (self.rt as u32 & 0b1111) << 12;
        encoding |= self.imm12 as u32 & 0b111111111111;
        encoding <<= 16;
        encoding |= self.rn as u32 & 0b1111;

        // Now we get the encoded opcode and stamp it on top of the instruction
        let opcode_encoding: u32 = self.opcode.into();
        encoding |= opcode_encoding;
        emit::<u32>(mem, encoding);
        Ok(())
    }
}

pub struct Imm12SplitTwoRegsEncoding {
    opcode: Thumb32OpcodeEncoding,
    rn: u8,
    rd: u8,
    imm12: u16,
}

impl Imm12SplitTwoRegsEncoding {
    pub fn new(opcode: Opcode, rn: u8, rd: u8, imm12: u16) -> Imm12SplitTwoRegsEncoding {
        Imm12SplitTwoRegsEncoding {
            opcode,
            rn,
            rd,
            imm12,
        }
    }
}

impl Emittable for Imm12SplitTwoRegsEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        // We first break up the immediate into its parts
        let i = (self.imm12 >> 11 & 0b1) as u32;
        let imm3 = ((self.imm12 >> 8) & 0b111) as u32;
        let imm8 = (self.imm12 & 0b11111111) as u32;

        // Because of the endianness of the machine (we are in Little Endian)
        // we need to encode the two words in reverse order.

        // We first write the operands
        encoding |= imm8;
        encoding |= (self.rd as u32 & 0b1111) << 8;
        encoding |= imm3 << 12;
        encoding <<= 16;
        encoding |= self.rn as u32 & 0b1111;
        encoding |= i << 10;

        // Now we get the encoded opcode and stamp it on top of the instruction
        let opcode_encoding: u32 = self.opcode.into();
        encoding |= opcode_encoding;
        emit::<u32>(mem, encoding);
        Ok(())
    }
}

pub struct Imm12OneRegEncoding {
    opcode: Thumb32OpcodeEncoding,
    rn: u8,
    imm12: u16,
}

impl Imm12OneRegEncoding {
    pub fn new(opcode: Opcode, rn: u8, imm12: u16) -> Imm12OneRegEncoding {
        Imm12OneRegEncoding {
            opcode,
            rn,
            imm12,
        }
    }
}

impl Emittable for Imm12OneRegEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;

        // We first break up the immediate into its parts
        let i = (self.imm12 >> 11 & 0b1) as u32;
        let imm3 = ((self.imm12 >> 8) & 0b111) as u32;
        let imm8 = (self.imm12 & 0b11111111) as u32;

        // Because of the endianness of the machine (we are in Little Endian)
        // we need to encode the two words in reverse order.

        // We first write the operands
        encoding |= imm8;
        encoding |= 0b1111 << 8;
        encoding |= imm3 << 12;
        encoding <<= 16;
        encoding |= self.rn as u32 & 0b1111;
        encoding |= i << 10;

        // Now we get the encoded opcode and stamp it on top of the instruction
        let opcode_encoding: u32 = self.opcode.into();
        encoding |= opcode_encoding;
        emit::<u32>(mem, encoding);
        Ok(())
    }
}

/// 32-bit Thumb encoding for instructions that have two registers
pub struct Imm8TwoRegsEncoding {
    opcode: Thumb32OpcodeEncoding,
    rn: u8,
    rt: u8,
    p: u8,
    u: u8,
    w: u8,
    imm8: u8,
}

impl Imm8TwoRegsEncoding {
    pub fn new(
        opcode: Thumb32OpcodeEncoding,
        rn: u8,
        rt: u8,
        p: u8,
        u: u8,
        w: u8,
        imm8: u8,
    ) -> Imm8TwoRegsEncoding {
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
        encoding |= self.rn as u32 & 0b1111;

        // We now get the encoded opcode and stamp it on top of the instruction
        let opcode_encoding: u32 = self.opcode.into();
        encoding |= opcode_encoding;
        emit::<u32>(mem, encoding);
        Ok(())
    }
}

pub struct Imm16OneRegEncoding {
    opcode: Thumb32OpcodeEncoding,
    rd: u8,
    imm16: u16,
}

impl Imm16OneRegEncoding {
    pub fn new(opcode: Thumb32OpcodeEncoding, rd: u8, imm16: u16) -> Self {
        Self { opcode, rd, imm16 }
    }
}

impl Emittable for Imm16OneRegEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;

        // First we split the immediate into its parts:
        let imm4 = (self.imm16 >> 12) as u32;
        let i = ((self.imm16 >> 11) & 0b1) as u32;
        let imm3 = ((self.imm16 >> 8) & 0b111) as u32;
        let imm8 = (self.imm16 & 0b11111111) as u32;

        // We first encode the lower word, shift it and then encode the higher word
        // to account for the Little Endian memory order.

        encoding |= imm8;
        encoding |= (self.rd as u32 & 0b1111) << 8;
        encoding |= imm3 << 12;

        encoding <<= 16;

        encoding |= imm4;
        encoding |= i << 10;

        // We now get the encoded opcode and stamp it on top of the instruction
        let opcode_encoding: u32 = self.opcode.into();
        encoding |= opcode_encoding;
        emit::<u32>(mem, encoding);

        Ok(())
    }
}

pub struct ThreeRegsEncoding {
    opcode: Thumb32OpcodeEncoding,
    rd: u8,
    rn: u8,
    rm: u8,
}

impl ThreeRegsEncoding {
    pub fn new(opcode: Thumb32OpcodeEncoding, rd: u8, rn: u8, rm: u8) -> Self {
        Self { opcode, rd, rn, rm }
    }
}

impl Emittable for ThreeRegsEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        // Because of the endianness of the machine (we are in Little Endian)
        // we need to encode the two words in reverse order.
        encoding |= self.rm as u32 & 0b1111;
        encoding |= 0b1111 << 4;
        encoding |= (self.rd as u32 & 0b1111) << 8;
        encoding |= 0b1111 << 12;

        encoding <<= 16;
        encoding |= self.rn as u32 & 0b1111;
        let opcode_encoding: u32 = self.opcode.into();
        encoding |= opcode_encoding;
        emit::<u32>(mem, encoding);
        Ok(())
    }
}

pub struct PopMultipleRegsEncoding {
    regs: Vec<u8>,
}

impl PopMultipleRegsEncoding {
    pub fn new(regs: Vec<u8>) -> Self {
        Self { regs }
    }
}

impl Emittable for PopMultipleRegsEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;

        let regs_encoding = self.regs.iter().fold(0, |acc, &reg| {
            acc | (1 << reg)
        });

        encoding |= regs_encoding as u32;
        encoding <<= 16;
        encoding |= 0b1101;
        let opcode_encoding: u32 = Opcode::new(0b01, 0b1011, 0b0).into();
        encoding |= opcode_encoding;
        emit::<u32>(mem, encoding);
        Ok(())
    }
}


pub struct PushMultipleRegsEncoding {
    regs: Vec<u8>,
}

impl PushMultipleRegsEncoding {
    pub fn new(regs: Vec<u8>) -> Self {
        Self { regs }
    }
}

impl Emittable for PushMultipleRegsEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;

        let regs_encoding = self.regs.iter().fold(0, |acc, &reg| {
            acc | (1 << reg)
        });

        encoding |= regs_encoding as u32;
        encoding <<= 16;
        encoding |= 0b1101;
        let opcode_encoding: u32 = Opcode::new(0b01, 0b10010, 0b0).into();
        encoding |= opcode_encoding;
        emit::<u32>(mem, encoding);
        Ok(())
    }
}
