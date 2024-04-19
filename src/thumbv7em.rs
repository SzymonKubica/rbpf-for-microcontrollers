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
    LogicalShiftLeftImmediate { imm5: u8, rm: u8, rd: u8 },
    LogicalShiftRightImmediate { imm5: u8, rm: u8, rd: u8 },
    ArithmeticShiftRightImmediate { imm5: u8, rm: u8, rd: u8 },
    Add { rm: u8, rn: u8, rd: u8 },
    Subtract { rm: u8, rn: u8, rd: u8 },
    Add3BitImmediate { imm3: u8, rn: u8, rd: u8 },
    Subtract3BitImmediate { imm3: u8, rn: u8, rd: u8 },
    MoveImmediate { rd: u8, imm8: u8 },
    CompareImmediate { rd: u8, imm8: u8 },
    Add8BitImmediate { rd: u8, imm8: u8 },
    Subtract8BitImmediate { rd: u8, imm8: u8 },
    // Data processing (operate mostly on registers)
    BitwiseAND { rm: u8, rd: u8 },
    ExclusiveOR { rm: u8, rd: u8 },
    LogicalShiftLeft { rm: u8, rd: u8 },
    LogicalShiftRight { rm: u8, rd: u8 },
    ArithmeticShiftRight { rm: u8, rd: u8 },
    AddWithCarry { rm: u8, rd: u8 },
    SubtractWithCarry { rm: u8, rd: u8 },
    RotateRight { rm: u8, rd: u8 },
    SetFlagsOnBitwiseAND { rm: u8, rd: u8 },
    ReverseSubtractFrom0 { rm: u8, rd: u8 },
    Compare { rm: u8, rd: u8 },
    CompareNegative { rm: u8, rd: u8 },
    LogicalOR { rm: u8, rd: u8 },
    MultiplyTwoRegisters { rm: u8, rd: u8 },
    BitClear { rm: u8, rd: u8 },
    BitwiseNOT { rm: u8, rd: u8 },
    // Special data instructions and branch and exchange
    AddRegistersSpecial { d: u8, rm: u8, rd: u8 },
    CompareRegistersSpecial { n: u8, rm: u8, rd: u8 },
    MoveRegistersSpecial { d: u8, rm: u8, rd: u8 },
    BranchAndExchange { rm: u8 },
    BranchWithLinkAndExchange { rm: u8 },
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
    ChangeProcessorState,
    AddImmediateToSP { imm: u16 },
    SubtractImmediateFromSP { imm: u16 },
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
    pub fn emit_into(&self, mem: &mut JitMemory) {
        let encoding = match self {
            // Shift (immediate), add, subtract, move, and compare
            ThumbInstruction::LogicalShiftLeftImmediate { imm5, rm, rd } => {
                const LSL_OPCODE: u8 = 0b00;
                Immediate5TwoRegistersEncoding::new(LSL_OPCODE, *imm5, *rm, *rd).encode()
            }
            ThumbInstruction::LogicalShiftRightImmediate { imm5, rm, rd } => {
                const LSR_OPCODE: u8 = 0b01;
                Immediate5TwoRegistersEncoding::new(LSR_OPCODE, *imm5, *rm, *rd).encode()
            }
            ThumbInstruction::ArithmeticShiftRightImmediate { imm5, rm, rd } => {
                const ASR_OPCODE: u8 = 0b10;
                Immediate5TwoRegistersEncoding::new(ASR_OPCODE, *imm5, *rm, *rd).encode()
            }
            ThumbInstruction::Add { rm, rn, rd } => {
                const ADD_OPCODE: u8 = 0b01100;
                ThreeRegistersEncoding::new(ADD_OPCODE, *rm, *rn, *rd).encode()
            }
            ThumbInstruction::Subtract { rm, rn, rd } => {
                const SUB_OPCODE: u8 = 0b01101;
                ThreeRegistersEncoding::new(SUB_OPCODE, *rm, *rn, *rd).encode()
            }
            ThumbInstruction::Add3BitImmediate { imm3, rn, rd } => {
                const ADD_OPCODE: u8 = 0b01110;
                Immediate3TwoRegistersEncoding::new(ADD_OPCODE, *imm3, *rn, *rd).encode()
            }
            ThumbInstruction::Subtract3BitImmediate { imm3, rn, rd } => {
                const SUB_OPCODE: u8 = 0b01111;
                Immediate3TwoRegistersEncoding::new(SUB_OPCODE, *imm3, *rn, *rd).encode()
            }
            ThumbInstruction::MoveImmediate { rd, imm8 } => {
                const MOV_OPCODE: u8 = 0b0100;
                Immediate8OneRegisterEncoding::new(MOV_OPCODE, *imm8, *rd).encode()
            }
            ThumbInstruction::CompareImmediate { rd, imm8 } => {
                const CPM_OPCODE: u8 = 0b0101;
                Immediate8OneRegisterEncoding::new(CPM_OPCODE, *imm8, *rd).encode()
            }
            ThumbInstruction::Add8BitImmediate { rd, imm8 } => {
                const SUB_OPCODE: u8 = 0b110;
                Immediate8OneRegisterEncoding::new(SUB_OPCODE, *imm8, *rd).encode()
            }
            ThumbInstruction::Subtract8BitImmediate { rd, imm8 } => {
                const SUB_OPCODE: u8 = 0b111;
                Immediate8OneRegisterEncoding::new(SUB_OPCODE, *imm8, *rd).encode()
            }
            // Data processing (operate mostly on registers)
            ThumbInstruction::BitwiseAND { rm, rd } => {
                const AND_OPCODE: u8 = 0b0000;
                TwoRegistersEncoding::new(AND_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::ExclusiveOR { rm, rd } => {
                const EOR_OPCODE: u8 = 0b0001;
                TwoRegistersEncoding::new(EOR_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::LogicalShiftLeft { rm, rd } => {
                const LSL_OPCODE: u8 = 0b0010;
                TwoRegistersEncoding::new(LSL_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::LogicalShiftRight { rm, rd } => {
                const LSR_OPCODE: u8 = 0b0011;
                TwoRegistersEncoding::new(LSR_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::ArithmeticShiftRight { rm, rd } => {
                const ASR_OPCODE: u8 = 0b0100;
                TwoRegistersEncoding::new(ASR_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::AddWithCarry { rm, rd } => {
                const ADC_OPCODE: u8 = 0b0101;
                TwoRegistersEncoding::new(ADC_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::SubtractWithCarry { rm, rd } => {
                const SBC_OPCODE: u8 = 0b0110;
                TwoRegistersEncoding::new(SBC_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::RotateRight { rm, rd } => {
                const ROR_OPCODE: u8 = 0b0111;
                TwoRegistersEncoding::new(ROR_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::SetFlagsOnBitwiseAND { rm, rd } => {
                const TST_OPCODE: u8 = 0b1000;
                TwoRegistersEncoding::new(TST_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::ReverseSubtractFrom0 { rm, rd } => {
                const RSB_OPCODE: u8 = 0b1001;
                TwoRegistersEncoding::new(RSB_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::Compare { rm, rd } => {
                const CMP_OPCODE: u8 = 0b1010;
                TwoRegistersEncoding::new(CMP_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::CompareNegative { rm, rd } => {
                const CMN_OPCODE: u8 = 0b1011;
                TwoRegistersEncoding::new(CMN_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::LogicalOR { rm, rd } => {
                const ORR_OPCODE: u8 = 0b1100;
                TwoRegistersEncoding::new(ORR_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::MultiplyTwoRegisters { rm, rd } => {
                const MUL_OPCODE: u8 = 0b1101;
                TwoRegistersEncoding::new(MUL_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::BitClear { rm, rd } => {
                const BIC_OPCODE: u8 = 0b1110;
                TwoRegistersEncoding::new(BIC_OPCODE, *rm, *rd).encode()
            }
            ThumbInstruction::BitwiseNOT { rm, rd } => {
                const MVN_OPCODE: u8 = 0b1111;
                TwoRegistersEncoding::new(MVN_OPCODE, *rm, *rd).encode()
            }
            // Special data instructions and branch and exchange
            ThumbInstruction::AddRegistersSpecial { d, rm, rd } => {
                const ADD_OPCODE: u8 = 0b00;
                TwoRegistersSpecialEncoding::new(ADD_OPCODE, *d, *rm, *rd).encode()
            }
            ThumbInstruction::CompareRegistersSpecial { n, rm, rd } => {
                const CMP_OPCODE: u8 = 0b01;
                TwoRegistersSpecialEncoding::new(CMP_OPCODE, *n, *rm, *rd).encode()
            }
            ThumbInstruction::MoveRegistersSpecial { d, rm, rd } => {
                const MOV_OPCODE: u8 = 0b10;
                TwoRegistersSpecialEncoding::new(MOV_OPCODE, *d, *rm, *rd).encode()
            }
            ThumbInstruction::BranchAndExchange { rm } => {
                const BX_OPCODE: u8 = 0b110;
                SpecialBranchEncoding::new(BX_OPCODE, *rm).encode()
            }
            ThumbInstruction::BranchWithLinkAndExchange { rm } => {
                const BLX_OPCODE: u8 = 0b111;
                SpecialBranchEncoding::new(BLX_OPCODE, *rm).encode()
            }
            // Load/store single data item
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
            ThumbInstruction::ChangeProcessorState => todo!(),
            // Miscellaneous 16-bit instructions
            ThumbInstruction::AddImmediateToSP {
                imm: immediate_offset,
            } => {
                const ADD_OPCODE: u8 = 0b1;
                SPPlusMinusImmediateEncoding::new(ADD_OPCODE, *immediate_offset).encode()
            }

            ThumbInstruction::SubtractImmediateFromSP {
                imm: immediate_offset,
            } => {
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

pub struct Immediate5TwoRegistersEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    imm5: u8,
    rm: u8,
    // Destination register
    rd: u8,
}

impl Immediate3TwoRegistersEncoding {
    pub fn new(opcode: u8, imm3: u8, rn: u8, rd: u8) -> Immediate3TwoRegistersEncoding {
        Immediate3TwoRegistersEncoding {
            class_opcode: BASIC,
            opcode,
            imm3,
            rn,
            rd,
        }
    }
}

impl Encoding for Immediate3TwoRegistersEncoding {
    fn encode(&self) -> u16 {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b11111) << 11;
        encoding |= (self.imm3 as u16 & 0b111) << 6;
        encoding |= (self.rn as u16 & 0b111) << 3;
        encoding |= self.rd as u16 & 0b111;
        encoding
    }
}

pub struct Immediate3TwoRegistersEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    // 3-bit immediate operand
    imm3: u8,
    rn: u8,
    // Destination register
    rd: u8,
}

impl Immediate5TwoRegistersEncoding {
    pub fn new(opcode: u8, imm5: u8, rm: u8, rd: u8) -> Immediate5TwoRegistersEncoding {
        Immediate5TwoRegistersEncoding {
            class_opcode: BASIC,
            opcode,
            imm5,
            rm,
            rd,
        }
    }
}

impl Encoding for Immediate5TwoRegistersEncoding {
    fn encode(&self) -> u16 {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b11) << 11;
        encoding |= (self.imm5 as u16 & 0b11111) << 6;
        encoding |= (self.rm as u16 & 0b111) << 3;
        encoding |= self.rd as u16 & 0b111;
        encoding
    }
}

pub struct Immediate8OneRegisterEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    // 8-bit immediate operand
    imm8: u8,
    // Destination register
    rd: u8,
}

impl Immediate8OneRegisterEncoding {
    pub fn new(opcode: u8, imm8: u8, rd: u8) -> Immediate8OneRegisterEncoding {
        Immediate8OneRegisterEncoding {
            class_opcode: BASIC,
            opcode,
            imm8,
            rd,
        }
    }
}

impl Encoding for Immediate8OneRegisterEncoding {
    fn encode(&self) -> u16 {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b111) << 11;
        encoding |= (self.rd as u16 & 0b111) << 8;
        encoding |= self.imm8 as u16 & 0b11111111;
        encoding
    }
}

pub struct ThreeRegistersEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    rm: u8,
    rn: u8,
    // Destination register
    rd: u8,
}

impl ThreeRegistersEncoding {
    pub fn new(opcode: u8, rm: u8, rn: u8, rd: u8) -> ThreeRegistersEncoding {
        ThreeRegistersEncoding {
            class_opcode: BASIC,
            opcode,
            rm,
            rn,
            rd,
        }
    }
}

impl Encoding for ThreeRegistersEncoding {
    fn encode(&self) -> u16 {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b11111) << 9;
        encoding |= (self.rm as u16 & 0b111) << 6;
        encoding |= (self.rn as u16 & 0b111) << 3;
        encoding |= self.rd as u16 & 0b111;
        encoding
    }
}

pub struct TwoRegistersEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    rm: u8,
    // Destination register
    rd: u8,
}

impl TwoRegistersEncoding {
    pub fn new(opcode: u8, rm: u8, rd: u8) -> TwoRegistersEncoding {
        TwoRegistersEncoding {
            class_opcode: DATA_PROCESSING,
            opcode,
            rm,
            rd,
        }
    }
}

impl Encoding for TwoRegistersEncoding {
    fn encode(&self) -> u16 {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b1111) << 6;
        encoding |= (self.rm as u16 & 0b111) << 3;
        encoding |= self.rd as u16 & 0b111;
        encoding
    }
}

pub struct TwoRegistersSpecialEncoding {
    class_opcode: InstructionClassOpcode,
    opcode: u8,
    dn_or_n_bit: u8,
    rm: u8,
    rd: u8,
}

impl TwoRegistersSpecialEncoding {
    pub fn new(opcode: u8, dn_or_n_bit: u8, rm: u8, rd: u8) -> TwoRegistersSpecialEncoding {
        TwoRegistersSpecialEncoding {
            class_opcode: SPECIAL_DATA_INSTRUCTIONS,
            opcode,
            dn_or_n_bit,
            rm,
            rd,
        }
    }
}

impl Encoding for TwoRegistersSpecialEncoding {
    fn encode(&self) -> u16 {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b11) << 8;
        encoding |= (self.dn_or_n_bit as u16 & 0b1) << 7;
        encoding |= (self.rm as u16 & 0b111) << 3;
        encoding |= self.rd as u16 & 0b111;
        encoding
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

impl Encoding for SpecialBranchEncoding {
    fn encode(&self) -> u16 {
        let mut encoding = 0;
        self.class_opcode.apply(&mut encoding);
        encoding |= (self.opcode as u16 & 0b111) << 7;
        encoding |= (self.rm as u16 & 0b111) << 3;
        encoding
    }
}
