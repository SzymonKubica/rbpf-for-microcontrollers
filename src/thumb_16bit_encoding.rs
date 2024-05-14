use crate::thumbv7em::{Condition};
use crate::{jit_thumbv7em::emit, JitMemory};
use log::debug;

use stdlib::{Error};

pub const INSTRUCTION_SIZE: u16 = 16;

/// Defines how to encode the opcode of 16-bit Thumb instructions. Instruction is layed out
/// as follows:
/// |------|----------|
/// _^opcode
#[derive(Debug, Clone, Copy)]
pub struct Thumb16OpcodeEncoding {
    pub class_opcode: InstructionClassOpcode,
    pub opcode: u8,
}

impl Thumb16OpcodeEncoding {
    pub const fn new(class_opcode: InstructionClassOpcode, opcode: u8) -> Thumb16OpcodeEncoding {
        Thumb16OpcodeEncoding {
            class_opcode,
            opcode,
        }
    }
}

/// Allows for encoding the instruction using the 16-bit or 32-bit Thumb encoding
pub trait Emittable {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error>;
}

/// Shift (immediate), add, subtract, move, and compare
pub const BASIC: InstructionClassOpcode = InstructionClassOpcode::new(0b00, 2);
/// Data processing (operate mostly on registers)
pub const DATA_PROCESSING: InstructionClassOpcode = InstructionClassOpcode::new(0b010000, 6);
/// Special data instructions and branch and exchange
pub const SPECIAL_DATA_INSTRUCTIONS: InstructionClassOpcode =
    InstructionClassOpcode::new(0b010001, 6);
/// Load/store single data item - this set of instructions doesn't have a fixed prefix
pub const LOAD_STORE_SINGLE_ITEM: InstructionClassOpcode = InstructionClassOpcode::new(0b0, 0);
/// Miscellaneous 16-bit instructions
pub const MISCELLANEOUS: InstructionClassOpcode = InstructionClassOpcode::new(0b1011, 4);
/// If-Then and hints
pub const IF_THEN_AND_HINTS: InstructionClassOpcode = InstructionClassOpcode::new(0b10111111, 8);
/// Conditional branch and supervisor call
pub const COND_BRANCH_AND_SUPERVISOR_CALL: InstructionClassOpcode =
    InstructionClassOpcode::new(0b1101, 4);

/// The beginning bits of each Thumb 16 instruction used to distinguish between
/// the different instruction class types. It has variable length as some instruction
/// classes have a fixed long opcode that doesn't change between members of the
/// class, whereasa others e.g. Load/Store single data item don't have a fixed
/// shared prefix at all.
#[derive(Debug, Clone, Copy)]
pub struct InstructionClassOpcode {
    opcode_value: u16,
    opcode_length: u16,
}

impl InstructionClassOpcode {
    pub const fn new(opcode_value: u16, opcode_length: u16) -> InstructionClassOpcode {
        InstructionClassOpcode {
            opcode_value,
            opcode_length,
        }
    }

    /// Inserts the opcode at its corresponding place into the mutable instruction
    /// encoding.
    pub fn apply(&self, encoding: &mut u16) {
        *encoding |= self.opcode_value << (INSTRUCTION_SIZE - self.opcode_length);
    }
}

pub struct PushPopEncoding {
    /// The shared prefix common for all members of the class
    class_opcode: InstructionClassOpcode,
    /// 3 bits specifying whether we have push or pop
    opcode: u8,
    /// The single bit in front of `register_list` specifying whether we
    /// push LR or pop PC
    m_p_bit: u8,
    /// The 8 bits of the register list, they allow for popping/pushing regs
    /// within range R0-R7
    register_list: u8,
}

impl PushPopEncoding {
    pub fn new(opcode: u8, m_p_bit: u8, register_list: u8) -> PushPopEncoding {
        PushPopEncoding {
            class_opcode: MISCELLANEOUS,
            opcode,
            m_p_bit,
            register_list,
        }
    }
}

impl Emittable for PushPopEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b111) << 9;
        encoding |= (self.m_p_bit as u16 & 0b1) << 8;
        encoding |= self.register_list as u16;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

pub struct SPPlusMinusImmediateEncoding {
    // The shared prefix common for all members of the class
    class_opcode: InstructionClassOpcode,
    // 5 bits specifying the instruction class member
    opcode: u8,
    // 7 bits specifying the immediate operand. Note that the specification of
    // the instruction shifts the immediate twice to the left, so the actual
    // value is of the immediate `imm7 << 2`, becuause of this, we can shift
    // the stack by at most 4 * 127 = 508 bytes.
    immediate: u16,
}

impl SPPlusMinusImmediateEncoding {
    pub fn new(opcode: u8, immediate: u16) -> SPPlusMinusImmediateEncoding {
        SPPlusMinusImmediateEncoding {
            class_opcode: MISCELLANEOUS,
            opcode,
            immediate,
        }
    }
}

impl Emittable for SPPlusMinusImmediateEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b1) << 7;
        encoding |= ((self.immediate >> 2) & 0b1111111) as u16;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

impl Imm3TwoRegsEncoding {
    pub fn new(opcode: u8, imm3: u8, rn: u8, rd: u8) -> Imm3TwoRegsEncoding {
        Imm3TwoRegsEncoding {
            class_opcode: BASIC,
            opcode,
            imm3,
            rn,
            rd,
        }
    }
}

impl Emittable for Imm3TwoRegsEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b11111) << 11;
        encoding |= (self.imm3 as u16 & 0b111) << 6;
        encoding |= (self.rn as u16 & 0b111) << 3;
        encoding |= self.rd as u16 & 0b111;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

pub struct Imm3TwoRegsEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    // 3-bit immediate operand
    imm3: u8,
    rn: u8,
    // Destination register
    rd: u8,
}

/// Thumb 16-bit encoding that has two 3-bit register fields and a 5-bit
/// immediate operand.
///
/// Note: both registers can only be from the range R0-R7 because their
/// numbers in the instruction are specified using 3 bits.
pub struct Imm5TwoRegsEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    imm5: u8,
    rm: u8,
    // Destination register
    rd: u8,
}

impl Imm5TwoRegsEncoding {
    pub fn new(
        class_opcode: InstructionClassOpcode,
        opcode: u8,
        imm5: u8,
        rm: u8,
        rd: u8,
    ) -> Imm5TwoRegsEncoding {
        Imm5TwoRegsEncoding {
            class_opcode,
            opcode,
            imm5,
            rm,
            rd,
        }
    }
}

impl Emittable for Imm5TwoRegsEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        let opcode_mask: u16 = match self.class_opcode.opcode_length {
            2 => 0b111,
            4 => 0b1,
            _ => panic!("Unexpected opcode length in Immediate5TwoRegistersEncoding"),
        };
        encoding |= (self.opcode as u16 & opcode_mask) << 11;
        encoding |= (self.imm5 as u16 & 0b11111) << 6;
        encoding |= (self.rm as u16 & 0b111) << 3;
        encoding |= self.rd as u16 & 0b111;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

pub struct Imm8OneRegEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    // 8-bit immediate operand
    imm8: u8,
    // Destination register
    rd: u8,
}

impl Imm8OneRegEncoding {
    pub fn new(
        class_opcode: InstructionClassOpcode,
        opcode: u8,
        imm8: u8,
        rd: u8,
    ) -> Imm8OneRegEncoding {
        Imm8OneRegEncoding {
            class_opcode,
            opcode,
            imm8,
            rd,
        }
    }
}

impl Emittable for Imm8OneRegEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        let opcode_mask: u16 = match self.class_opcode.opcode_length {
            2 => 0b111,
            4 => 0b1,
            _ => panic!("Unexpected opcode length in Immediate8OneRegisterEncoding"),
        };
        encoding |= (self.opcode as u16 & opcode_mask) << 11;
        encoding |= (self.rd as u16 & 0b111) << 8;
        encoding |= self.imm8 as u16 & 0b11111111;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

/// Thumb 16-bit encoding that that operates on three registers from range
/// R0-R7. The encoding has 3 3-bit register fields.
///
/// **Note**: `rm`, `rn` and `rd` can only be from the range R0-R7, otherwise
/// they will be 'clipped' to 3 bits and one might emit wrong instructions.
pub struct ThreeRegsEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    rm: u8,
    rn: u8,
    // Destination register
    rd: u8,
}

impl ThreeRegsEncoding {
    pub fn new(
        class_opcode: InstructionClassOpcode,
        opcode: u8,
        rm: u8,
        rn: u8,
        rd: u8,
    ) -> ThreeRegsEncoding {
        ThreeRegsEncoding {
            class_opcode,
            opcode,
            rm,
            rn,
            rd,
        }
    }
}

impl Emittable for ThreeRegsEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        // The three registers encoding is used both for basic ADD and
        // STR instructions, in the latter case the specific `opcode` length
        // is smaller so we need to adjust the mask depending on the length
        // of the class opcode.
        let opcode_mask = match self.class_opcode.opcode_length {
            2 => 0b11111,
            4 => 0b111,
            _ => panic!("Unexpected opcode length in ThreeRegistersEncoding"),
        };
        encoding |= (self.opcode as u16 & opcode_mask) << 9;
        encoding |= (self.rm as u16 & 0b111) << 6;
        encoding |= (self.rn as u16 & 0b111) << 3;
        encoding |= self.rd as u16 & 0b111;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

pub struct TwoRegsEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    rm: u8,
    // Destination register
    rd: u8,
}

impl TwoRegsEncoding {
    pub fn new(
        class_opcode: InstructionClassOpcode,
        opcode: u8,
        rm: u8,
        rd: u8,
    ) -> TwoRegsEncoding {
        TwoRegsEncoding {
            class_opcode,
            opcode,
            rm,
            rd,
        }
    }
}

impl Emittable for TwoRegsEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        // The first one is used in case of DATA_PROCESSING instruction class and the
        // second one is used for the MISCELLANEOUS UXTH.. etc.
        let opcode_mask = match self.class_opcode.opcode_length {
            6 => 0b1111,
            4 => 0b111111,
            _ => panic!("Unexpected opcode length in Immediate5TwoRegistersEncoding"),
        };
        encoding |= (self.opcode as u16 & opcode_mask) << 6;
        encoding |= (self.rm as u16 & 0b111) << 3;
        encoding |= self.rd as u16 & 0b111;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

pub struct TwoRegistersSpecialEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    rm: u8,
    rd: u8,
}

impl TwoRegistersSpecialEncoding {
    pub fn new(opcode: u8, rm: u8, rd: u8) -> TwoRegistersSpecialEncoding {
        TwoRegistersSpecialEncoding {
            class_opcode: SPECIAL_DATA_INSTRUCTIONS,
            opcode,
            rm,
            rd,
        }
    }
}

impl Emittable for TwoRegistersSpecialEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b11) << 8;
        // According to the specification, the bits of the Rd (or Rn in case of comparison)
        // are split into two chunks: D:rd where the D bit specified before rM
        // like so `D:Rm:Rd`. The specification also says that it only works
        // on Thumb if not both of the registers are from range R0-R7.
        let d_bit = self.rd >> 3;
        encoding |= (d_bit as u16 & 0b1) << 7;
        encoding |= (self.rm as u16 & 0b1111) << 3;
        encoding |= self.rd as u16 & 0b111;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

pub struct SpecialBranchEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    rm: u8,
}

impl SpecialBranchEncoding {
    pub fn new(opcode: u8, rm: u8) -> SpecialBranchEncoding {
        SpecialBranchEncoding {
            class_opcode: SPECIAL_DATA_INSTRUCTIONS,
            opcode,
            rm,
        }
    }
}

impl Emittable for SpecialBranchEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b111) << 7;
        encoding |= (self.rm as u16 & 0b1111) << 3;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

pub struct CompareAndBranchEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    i: u8,
    imm5: u8,
    rn: u8,
}

impl CompareAndBranchEncoding {
    pub fn new(opcode: u8, i: u8, imm5: u8, rn: u8) -> CompareAndBranchEncoding {
        CompareAndBranchEncoding {
            class_opcode: MISCELLANEOUS,
            opcode,
            i,
            imm5,
            rn,
        }
    }
}

impl Emittable for CompareAndBranchEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b1) << 11;
        encoding |= (self.i as u16 & 0b1) << 9;
        encoding |= 0b1 << 8;
        encoding |= (self.imm5 as u16 & 0b11111) << 3;
        encoding |= self.rn as u16 & 0b111;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

pub struct ConditionalBranchEncoding {
    class_opcode: InstructionClassOpcode,
    cond: Condition,
    imm: i8,
}

impl ConditionalBranchEncoding {
    pub fn new(cond: Condition, imm: i8) -> ConditionalBranchEncoding {
        ConditionalBranchEncoding {
            class_opcode: COND_BRANCH_AND_SUPERVISOR_CALL,
            cond,
            imm,
        }
    }
}

impl Emittable for ConditionalBranchEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        // The immediate fits into the encoding T1
        let mut encoding = 0;
        debug!(
            "Writing conditional branch with offset as u8: {} ({:#x})",
            self.imm as u8, self.imm as u8
        );
        debug!(
            "Writing conditional branch with offset: {} ({:#x})",
            self.imm, self.imm
        );
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.cond as u16 & 0b1111) << 8;
        // Here the cast as u8 is needed because negative numbers will
        // have lots of 1s in front of them after casting to u16 which will
        // corrupt the higher bits of the encoding.
        encoding |= (self.imm as u8) as u16;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}

pub struct HintEncoding {
    pub op_a: u8,
    pub op_b: u8,
}

impl HintEncoding {
    pub fn new(op_a: u8, op_b: u8) -> HintEncoding {
        HintEncoding { op_a, op_b }
    }
}

impl Emittable for HintEncoding {
    fn emit(&self, mem: &mut JitMemory) -> Result<(), Error> {
        let mut encoding = 0;
        IF_THEN_AND_HINTS.apply(&mut encoding);
        encoding |= (self.op_a as u16 & 0b1111) << 8;
        encoding |= self.op_b as u16;
        emit::<u16>(mem, encoding);
        Ok(())
    }
}
