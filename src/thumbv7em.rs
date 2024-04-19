use crate::{jit_thumbv7em::emit, JitMemory};
use stdlib::collections::Vec;

// Registers
pub const R0: u8 = 0;
pub const R1: u8 = 1;
pub const R2: u8 = 2;
pub const R3: u8 = 3;
pub const R4: u8 = 4;
pub const R5: u8 = 5;
pub const R6: u8 = 6;
pub const R7: u8 = 7;
pub const R8: u8 = 8;
pub const R9: u8 = 9;
pub const R10: u8 = 10;
pub const R11: u8 = 11;
pub const R12: u8 = 12;
pub const SP: u8 = 13;
pub const LR: u8 = 14;
pub const PC: u8 = 15;

pub const ARGUMENT_REGISTERS: [u8; 4] = [R0, R1, R2, R3];

// The short 16b version of push multiple doesn't allow for pushing registers
// other than R0-R7 and LR so we can only save those
pub const CALLEE_SAVED_REGISTERS: [u8; 4] = [R4, R5, R6, R7];

pub const INSTRUCTION_SIZE: u16 = 16;

/// The 16b Thumb instructions subset of the ARMv7-M ISA. They are taken directly
/// from the ARMv7-M Architecture Reference Manual without renaming / abstracting
/// out common patterns to allow for easier debugging and consulting the docs.
///
/// By convention, if the enum member name ends with Immediate, then the instruction
/// includes the immediate operand, otherwise the instruction operates purely on
/// registers.
pub enum ThumbInstruction {
    // Shift (immediate), add, subtract, move, and compare
    LogicalShiftLeftImmediate,
    LogicalShiftRightImmediate,
    ArithmeticShiftRightASRImmediate,
    Add,
    Subtract,
    Add3BitImmediate,
    Subtract3BitImmediate,
    MoveImmediate,
    CompareImmediate,
    Add8BitImmediate,
    Subtract8BitImmediate,
    // Data processing (operate mostly on registers)
    BitwiseAND,
    ExclusiveOR,
    LogicalShiftLeft,
    LogicalShiftRight,
    ArithmeticShiftRight,
    AddWithCarry,
    SubtractWithCarry,
    RotateRight,
    SetFlagsOnBitwiseAND,
    ReverseSubtractFrom0,
    Compare,
    CompareNegative,
    LogicalOR,
    MultiplyTwoRegisters,
    BitClear,
    BitwiseNOT,
    // Special data instructions and branch and exchange
    AddRegistersSpecial,
    CompareRegistersSpecial,
    MoveRegistersSpecial,
    BranchAndExchange,
    BranchWithLinkAndExchange,
    // Load/store single data item
    StoreRegister,
    StoreRegisterHalfword,
    StoreRegisterByte,
    LoadRegisterSignedByte,
    LoadRegister,
    LoadRegisterHalfword,
    LoadRegisterByte,
    LoadRegisterSignedHalfword,
    StoreRegisterImmediate,
    LoadRegisterImmediate,
    StoreRegisterByteImmediate,
    LoadRegisterByteImmediate,
    StoreRegisterHalfwordImmediate,
    LoadRegisterHalfwordImmediate,
    StoreRegisterSPRelativeImmediate,
    LoadRegisterSPRelativeImmediate,
    // Miscellaneous 16-bit instructions
    ChangeProcessorStateCPSon,
    AddImmediateToSP { immediate_offset: u16 },
    SubtractImmediateFromSP { immediate_offset: u16 },
    CompareAndBranchOnZero,
    SignedExtendHalfword,
    SignedExtendByte,
    UnsignedExtendHalfword,
    UnsignedExtendByte,
    PushMultipleRegisters { registers: Vec<u8> },
    ByteReverseWord,
    ByteReversePackedHalfword,
    ByteReverseSignedHalfword,
    CompareAndBranchOnNonZero,
    PopMultipleRegisters { registers: Vec<u8> },
    Breakpoint,
    // If-Then and hints
    IfThen,
    NoOperationHint,
    YieldHint,
    WaitForEventHint,
    WaitForInterruptHint,
    SendEventHint,
    // Conditional branch and supervisor call
    ConditionalBranch,
    SupervisorCall,
}

impl ThumbInstruction {
    pub fn emit(&self, mem: &mut JitMemory) {
        let encoding = match self {
            ThumbInstruction::LogicalShiftLeftImmediate => todo!(),
            ThumbInstruction::LogicalShiftRightImmediate => todo!(),
            ThumbInstruction::ArithmeticShiftRightASRImmediate => todo!(),
            ThumbInstruction::Add => todo!(),
            ThumbInstruction::Subtract => todo!(),
            ThumbInstruction::Add3BitImmediate => todo!(),
            ThumbInstruction::Subtract3BitImmediate => todo!(),
            ThumbInstruction::MoveImmediate => todo!(),
            ThumbInstruction::CompareImmediate => todo!(),
            ThumbInstruction::Add8BitImmediate => todo!(),
            ThumbInstruction::Subtract8BitImmediate => todo!(),
            ThumbInstruction::BitwiseAND => todo!(),
            ThumbInstruction::ExclusiveOR => todo!(),
            ThumbInstruction::LogicalShiftLeft => todo!(),
            ThumbInstruction::LogicalShiftRight => todo!(),
            ThumbInstruction::ArithmeticShiftRight => todo!(),
            ThumbInstruction::AddWithCarry => todo!(),
            ThumbInstruction::SubtractWithCarry => todo!(),
            ThumbInstruction::RotateRight => todo!(),
            ThumbInstruction::SetFlagsOnBitwiseAND => todo!(),
            ThumbInstruction::ReverseSubtractFrom0 => todo!(),
            ThumbInstruction::Compare => todo!(),
            ThumbInstruction::CompareNegative => todo!(),
            ThumbInstruction::LogicalOR => todo!(),
            ThumbInstruction::MultiplyTwoRegisters => todo!(),
            ThumbInstruction::BitClear => todo!(),
            ThumbInstruction::BitwiseNOT => todo!(),
            ThumbInstruction::AddRegistersSpecial => todo!(),
            ThumbInstruction::CompareRegistersSpecial => todo!(),
            ThumbInstruction::MoveRegistersSpecial => todo!(),
            ThumbInstruction::BranchAndExchange => todo!(),
            ThumbInstruction::BranchWithLinkAndExchange => todo!(),
            ThumbInstruction::StoreRegister => todo!(),
            ThumbInstruction::StoreRegisterHalfword => todo!(),
            ThumbInstruction::StoreRegisterByte => todo!(),
            ThumbInstruction::LoadRegisterSignedByte => todo!(),
            ThumbInstruction::LoadRegister => todo!(),
            ThumbInstruction::LoadRegisterHalfword => todo!(),
            ThumbInstruction::LoadRegisterByte => todo!(),
            ThumbInstruction::LoadRegisterSignedHalfword => todo!(),
            ThumbInstruction::StoreRegisterImmediate => todo!(),
            ThumbInstruction::LoadRegisterImmediate => todo!(),
            ThumbInstruction::StoreRegisterByteImmediate => todo!(),
            ThumbInstruction::LoadRegisterByteImmediate => todo!(),
            ThumbInstruction::StoreRegisterHalfwordImmediate => todo!(),
            ThumbInstruction::LoadRegisterHalfwordImmediate => todo!(),
            ThumbInstruction::StoreRegisterSPRelativeImmediate => todo!(),
            ThumbInstruction::LoadRegisterSPRelativeImmediate => todo!(),
            ThumbInstruction::ChangeProcessorStateCPSon => todo!(),
            ThumbInstruction::AddImmediateToSP { immediate_offset } => {
                const ADD_OPCODE: u8 = 0b1;
                SPPlusMinusImmediateEncoding::new(ADD_OPCODE, *immediate_offset).encode()
            }

            ThumbInstruction::SubtractImmediateFromSP { immediate_offset } => {
                const SUBTRACT_OPCODE: u8 = 0b0;
                SPPlusMinusImmediateEncoding::new(SUBTRACT_OPCODE, *immediate_offset).encode()
            }
            ThumbInstruction::CompareAndBranchOnZero => todo!(),
            ThumbInstruction::SignedExtendHalfword => todo!(),
            ThumbInstruction::SignedExtendByte => todo!(),
            ThumbInstruction::UnsignedExtendHalfword => todo!(),
            ThumbInstruction::UnsignedExtendByte => todo!(),
            ThumbInstruction::PushMultipleRegisters { registers } => {
                const PUSH_OPCODE: u8 = 0b010;
                let mut reg_list: u8 = 0;
                for reg in registers {
                    if reg != &LR {
                        reg_list |= 1 << reg;
                    }
                }
                let m = if registers.contains(&LR) { 1 } else { 0 };

                PushPopEncoding::new(PUSH_OPCODE, m, reg_list).encode()
            }
            ThumbInstruction::ByteReverseWord => todo!(),
            ThumbInstruction::ByteReversePackedHalfword => todo!(),
            ThumbInstruction::ByteReverseSignedHalfword => todo!(),
            ThumbInstruction::CompareAndBranchOnNonZero => todo!(),
            ThumbInstruction::PopMultipleRegisters { registers } => {
                let mut reg_list: u8 = 0;
                for reg in registers {
                    if reg != &PC {
                        reg_list |= 1 << reg;
                    }
                }
                const POP_OPCODE: u8 = 0b110;
                let p = if registers.contains(&PC) { 1 } else { 0 };

                PushPopEncoding::new(POP_OPCODE, p, reg_list).encode()
            }

            ThumbInstruction::Breakpoint => todo!(),
            ThumbInstruction::IfThen => todo!(),
            ThumbInstruction::NoOperationHint => todo!(),
            ThumbInstruction::YieldHint => todo!(),
            ThumbInstruction::WaitForEventHint => todo!(),
            ThumbInstruction::WaitForInterruptHint => todo!(),
            ThumbInstruction::SendEventHint => todo!(),
            ThumbInstruction::ConditionalBranch => todo!(),
            ThumbInstruction::SupervisorCall => todo!(),
        };

        emit::<u16>(mem, encoding)
    }
}

// All instruction classes with their corresponding opcodes defined

/// Shift (immediate), add, subtract, move, and compare
pub const BASIC: InstructionClassOpcode = InstructionClassOpcode::new(0b00, 2);
/// Data processing (operate mostly on registers)
pub const DATA_PROCESSING: InstructionClassOpcode = InstructionClassOpcode::new(0b01000, 6);
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

pub trait Encoding {
    fn encode(&self) -> u16;
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

impl Encoding for PushPopEncoding {
    fn encode(&self) -> u16 {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b111) << 9;
        encoding |= (self.m_p_bit as u16 & 0b1) << 8;
        encoding |= self.register_list as u16;
        encoding
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

impl Encoding for SPPlusMinusImmediateEncoding {
    fn encode(&self) -> u16 {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b1) << 7;
        encoding |= ((self.immediate >> 2) & 0b1111111) as u16;
        encoding
    }
}
