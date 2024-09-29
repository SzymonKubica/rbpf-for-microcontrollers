use crate::jit_thumbv7em::{SPILL_REG1, SPILL_REG2};
use crate::thumb_16bit_encoding::{
    self as thumb16, Emittable, InstructionClassOpcode, Thumb16OpcodeEncoding, BASIC,
    DATA_PROCESSING, MISCELLANEOUS,
};
use crate::thumb_32bit_encoding::{self as thumb32, Thumb32OpcodeEncoding};
use crate::{jit_thumbv7em::emit, JitMemory};
use log::debug;
use crate::lib::*;

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

pub const CALLEE_SAVED_REGISTERS: [u8; 7] = [R4, R5, R6, R7, R8, R10, R11];

#[derive(Debug, Clone, Copy)]
pub enum Condition {
    /// Equal
    EQ = 0b0000,
    /// Not equal
    NE = 0b0001,
    /// Carry set
    CS = 0b0010,
    /// Carry clear
    CC = 0b0011,
    /// Negative
    MI = 0b0100,
    /// Positive or zero
    PL = 0b0101,
    /// Overflow
    VS = 0b0110,
    /// No overflow
    VC = 0b0111,
    /// Unsigned higher
    HI = 0b1000,
    /// Unsigned lower or same
    LS = 0b1001,
    /// Signed greater than or equal
    GE = 0b1010,
    /// Signed less than
    LT = 0b1011,
    /// Signed greater than
    GT = 0b1100,
    /// Signed less than or equal
    LE = 0b1101,
    /// Always (unconditional)
    AL = 0b1110,
}

/// The 16b Thumb instructions subset of the ARMv7-M ISA. They are taken directly
/// from the ARMv7-M Architecture Reference Manual without renaming / abstracting
/// out common patterns to allow for easier debugging and consulting the docs.
///
/// By convention, if the enum member name ends with Immediate, then the instruction
/// includes the immediate operand, otherwise the instruction operates purely on
/// registers.
pub enum ThumbInstruction {
    // Shift (immediate), add, subtract, move, and compare
    LogicalShiftLeftImmediate {
        imm5: u8,
        rm: u8,
        rd: u8,
    },
    LogicalShiftRightImmediate {
        imm5: u8,
        rm: u8,
        rd: u8,
    },
    ArithmeticShiftRightImmediate {
        imm5: u8,
        rm: u8,
        rd: u8,
    },
    Add {
        rm: u8,
        rn: u8,
        rd: u8,
    },
    /// Subtract (register) subtracts an optionally-shifted register value `rm` from a register value `rn`, and writes the result to the
    /// destination register `rd`. It can optionally update the condition flags based on the result.
    Subtract {
        rm: u8,
        rn: u8,
        rd: u8,
    },
    Add3BitImmediate {
        imm3: u8,
        rn: u8,
        rd: u8,
    },
    Add12BitImmediate {
        imm12: u16,
        rn: u8,
        rd: u8,
    },
    Subtract3BitImmediate {
        imm3: u8,
        rn: u8,
        rd: u8,
    },
    Subtract12BitImmediate {
        imm12: u16,
        rn: u8,
        rd: u8,
    },
    MoveImmediate {
        rd: u8,
        imm: i32,
    },
    CompareImmediate {
        rd: u8,
        imm: i32,
    },
    Add8BitImmediate {
        rd: u8,
        imm8: u8,
    },
    Subtract8BitImmediate {
        rd: u8,
        imm8: u8,
    },
    // Data processing (operate mostly on registers)
    BitwiseAND {
        rm: u8,
        rd: u8,
    },
    ExclusiveOR {
        rm: u8,
        rd: u8,
    },
    LogicalShiftLeft {
        rm: u8,
        rd: u8,
    },
    LogicalShiftRight {
        rm: u8,
        rd: u8,
    },
    ArithmeticShiftRight {
        rm: u8,
        rd: u8,
    },
    AddWithCarry {
        rm: u8,
        rd: u8,
    },
    SubtractWithCarry {
        rm: u8,
        rd: u8,
    },
    RotateRight {
        rm: u8,
        rd: u8,
    },
    SetFlagsOnBitwiseAND {
        rm: u8,
        rd: u8,
    },
    ReverseSubtractFrom0 {
        rm: u8,
        rd: u8,
    },
    CompareRegisters {
        rm: u8,
        rd: u8,
    },
    CompareNegative {
        rm: u8,
        rd: u8,
    },
    LogicalOR {
        rm: u8,
        rd: u8,
    },
    MultiplyTwoRegisters {
        rm: u8,
        rd: u8,
    },
    /// Signed Divide divides a 32-bit signed integer register value `rn` by a 32-bit signed
    /// integer register value `rm`, and writes the result to the destination register `rd`.
    /// The condition code flags are not affected.
    SignedDivide {
        rd: u8,
        rm: u8,
        rn: u8,
    },
    BitClear {
        rm: u8,
        rd: u8,
    },
    BitwiseNOT {
        rm: u8,
        rd: u8,
    },
    // Special data instructions and branch and exchange
    AddRegistersSpecial {
        rm: u8,
        rd: u8,
    },
    CompareRegistersShift {
        rm: u8,
        rd: u8,
        shift: u8,
    },
    MoveRegistersSpecial {
        rm: u8,
        rd: u8,
    },
    BranchAndExchange {
        rm: u8,
    },
    BranchWithLinkAndExchange {
        rm: u8,
    },
    // Load/store single data item
    /// Rt contains the data to store, Rn is the base address and Rm is the
    /// offset register
    StoreRegister {
        rm: u8,
        rn: u8,
        rt: u8,
    },
    StoreRegisterSPRelative {
        rt: u8,
        imm8: u8,
    },
    StoreRegisterHalfword {
        rm: u8,
        rn: u8,
        rt: u8,
    },
    StoreRegisterByte {
        rm: u8,
        rn: u8,
        rt: u8,
    },
    LoadRegisterSignedByte {
        rm: u8,
        rn: u8,
        rt: u8,
    },
    LoadRegister {
        rm: u8,
        rn: u8,
        rt: u8,
    },
    LoadRegisterHalfword {
        rm: u8,
        rn: u8,
        rt: u8,
    },
    LoadRegisterByte {
        rm: u8,
        rn: u8,
        rt: u8,
    },
    LoadRegisterSignedHalfword {
        rm: u8,
        rn: u8,
        rt: u8,
    },
    /// Store Register (immediate) calculates an address from a base register (`rn`) value and an
    /// immediate offset (`imm`), and stores a word from a register (`tn`) to memory.
    /// Note: it only supports positive offsets (as it uses ZeroExtend for immediate operands)
    /// In order to do a store with negative offset one needs to store the negative
    /// value into a register and use StoreRegister
    StoreRegisterImmediate {
        imm: i16,
        rn: u8,
        rt: u8,
    },
    LoadRegisterImmediate {
        imm: i16,
        rn: u8,
        rt: u8,
    },
    StoreRegisterByteImmediate {
        imm: i16,
        rn: u8,
        rt: u8,
    },
    LoadRegisterByteImmediate {
        imm: i16,
        rn: u8,
        rt: u8,
    },
    StoreRegisterHalfwordImmediate {
        imm: i16,
        rn: u8,
        rt: u8,
    },
    LoadRegisterHalfwordImmediate {
        imm: i16,
        rn: u8,
        rt: u8,
    },
    // Miscellaneous 16-bit instructions
    AddImmediateToSP {
        imm: u16,
    },
    SubtractImmediateFromSP {
        imm: u16,
    },
    CompareAndBranchOnZero {
        i: u8,
        imm5: u8,
        rn: u8,
    },
    SignedExtendHalfword {
        rm: u8,
        rd: u8,
    },
    SignedExtendByte {
        rm: u8,
        rd: u8,
    },
    UnsignedExtendHalfword {
        rm: u8,
        rd: u8,
    },
    UnsignedExtendByte {
        rm: u8,
        rd: u8,
    },
    PushMultipleRegisters {
        registers: Vec<u8>,
    },
    ByteReverseWord {
        rm: u8,
        rd: u8,
    },
    ByteReversePackedHalfword {
        rm: u8,
        rd: u8,
    },
    ByteReverseSignedHalfword {
        rm: u8,
        rd: u8,
    },
    CompareAndBranchOnNonZero {
        i: u8,
        imm5: u8,
        rn: u8,
    },
    PopMultipleRegisters {
        registers: Vec<u8>,
    },
    // If-Then and hints (not useful for now)
    // IfThen,
    NoOperationHint,
    // YieldHint,
    // WaitForEventHint,
    // WaitForInterruptHint,
    // SendEventHint,
    // Conditional branch and supervisor call
    /// Causes a jump to at target address specified an offset from the current
    /// PC value. The current PC value of a given instruction is equal to the
    /// address of the instruction + 4. Because of this, when translating jump
    /// offsets from eBPF to ARM we need to subtract 1 from the resulting
    /// ARM offset to account for the fact that PC value is address + 4
    ConditionalBranch {
        cond: Condition,
        imm: i32,
    },
    // An empty instruction inserted in place of conditional branches
    // before their offsets get resolved.
    BlankInstruction,
    //SupervisorCall,
}

impl ThumbInstruction {
    pub fn emit_into(&self, mem: &mut JitMemory) -> Result<(), Error> {
        match self {
            // Shift (immediate), add, subtract, move, and compare
            ThumbInstruction::LogicalShiftLeftImmediate { imm5, rm, rd } => {
                if *rm > 8 || *rd > 8 {
                    let opcode = Thumb32OpcodeEncoding::new(0b01, 0b0100100, 0b0);
                    thumb32::Imm5LSLTwoRegsEncoding::new(opcode, *rm, *rd, *imm5).emit(mem)
                } else {
                    const LSL_OPCODE: u8 = 0b00;
                    thumb16::Imm5TwoRegsEncoding::new(BASIC, LSL_OPCODE, *imm5, *rm, *rd).emit(mem)
                }
            }
            ThumbInstruction::LogicalShiftRightImmediate { imm5, rm, rd } => {
                const LSR_OPCODE: u8 = 0b01;
                thumb16::Imm5TwoRegsEncoding::new(BASIC, LSR_OPCODE, *imm5, *rm, *rd).emit(mem)
            }
            ThumbInstruction::ArithmeticShiftRightImmediate { imm5, rm, rd } => {
                const ASR_OPCODE: u8 = 0b10;
                thumb16::Imm5TwoRegsEncoding::new(BASIC, ASR_OPCODE, *imm5, *rm, *rd).emit(mem)
            }
            ThumbInstruction::Add { rm, rn, rd } => {
                const ADD_OPCODE: u8 = 0b01100;
                thumb16::ThreeRegsEncoding::new(BASIC, ADD_OPCODE, *rm, *rn, *rd).emit(mem)
            }
            ThumbInstruction::Subtract { rm, rn, rd } => {
                const SUB_OPCODE: u8 = 0b01101;
                thumb16::ThreeRegsEncoding::new(BASIC, SUB_OPCODE, *rm, *rn, *rd).emit(mem)
            }
            ThumbInstruction::Add3BitImmediate { imm3, rn, rd } => {
                const ADD_OPCODE: u8 = 0b01110;
                thumb16::Imm3TwoRegsEncoding::new(ADD_OPCODE, *imm3, *rn, *rd).emit(mem)
            }
            ThumbInstruction::Subtract3BitImmediate { imm3, rn, rd } => {
                const SUB_OPCODE: u8 = 0b01111;
                thumb16::Imm3TwoRegsEncoding::new(SUB_OPCODE, *imm3, *rn, *rd).emit(mem)
            }
            ThumbInstruction::MoveImmediate { rd, imm } => {
                // We use different encodings based on the size of the immediate.
                if 0 < *imm && (*imm as u32) >= (1 << 16) {
                    // We could use the ThumbExpandImm encoding to represent larger
                    // numbers, however this has a limitation that not all 32-bit
                    // numbers are expressible using that encoding. For instance
                    // in case of helper function calls, we need to load the 32-bit
                    // address of a function into a register, and often it is a bit-string
                    // which isn't expressible using ThumbExpandImm. For instance
                    // we could get and address like 0x8015663 which in binary
                    // is 1000000000010101011001100011 and that has non-zero
                    // bits in all four bytes of the 32-bit value, and it doesn't have
                    // a repeating pattern. Because of this one cannot use ThumbExpandImm
                    // to represent it. Instead we load the higher 16 bits into the
                    // target register first, then lsl it by 16 bits and then
                    // add the remaining 16 bits to it.

                    let higher_halfword = (*imm >> 16) as u16;
                    let lower_halfword = *imm as u16;

                    ThumbInstruction::MoveImmediate {
                        rd: *rd,
                        imm: higher_halfword as i32,
                    }
                    .emit_into(mem)?;
                    ThumbInstruction::LogicalShiftLeftImmediate {
                        imm5: 16,
                        rm: *rd,
                        rd: *rd,
                    }
                    .emit_into(mem)?;
                    ThumbInstruction::MoveImmediate {
                        rd: SPILL_REG2,
                        imm: lower_halfword as i32,
                    }
                    .emit_into(mem)?;
                    return ThumbInstruction::AddRegistersSpecial {
                        rm: SPILL_REG2,
                        rd: *rd,
                    }
                    .emit_into(mem);
                }

                // If the immediate is negative, we have a problem as we need
                // to use the encoding T2 which uses the ThumbExpandImm procedure
                // when transforming the instruction immediate into the actual value
                // that the CPU gets. Because of this we need to get around it
                // by moving 0 into the target register and then subtracting the
                // desired value from it. The ideal solution would be to use
                // the ThumbExpandImm encoding correctly but for that we need
                // an inverse function that given a desired immediate value would
                // yield the encoding that produces it after applying ThumbExpandImm
                // which we currently don't have.
                if *imm < 0 {
                    if imm.abs() >= (1 << 8) {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("[JIT] Instruction MOV with negative immediate {:#x} which does not fit into 8 bits.", imm),));
                    }
                    ThumbInstruction::MoveImmediate { rd: *rd, imm: 0 }.emit_into(mem)?;
                    return ThumbInstruction::Subtract8BitImmediate {
                        rd: *rd,
                        imm8: (-1 * imm) as u8,
                    }
                    .emit_into(mem);
                }

                if (*imm as u16) < (1 << 8) && *rd < 8 {
                    const MOV_OPCODE: u8 = 0b0100;
                    // For this one the only allowed registers are R0-R7
                    return thumb16::Imm8OneRegEncoding::new(BASIC, MOV_OPCODE, *imm as u8, *rd)
                        .emit(mem);
                } else {
                    let opcode = Thumb32OpcodeEncoding::new(0b10, 0b100100, 0b0);
                    return thumb32::Imm16OneRegEncoding::new(opcode, *rd, *imm as u16).emit(mem);
                }
            }
            ThumbInstruction::CompareImmediate { rd, imm } => {
                if 0 < *imm && *imm < (1 << 8) {
                    const CPM_OPCODE: u8 = 0b0101;
                    return thumb16::Imm8OneRegEncoding::new(BASIC, CPM_OPCODE, *imm as u8, *rd)
                        .emit(mem);
                } else {
                    /* This encoding transforms the immediate operand using the
                     * ThumbExpandImm which is not implemented yet. In short
                     * the way it works is that it uses the top 4 bits of the immediate
                     * to determine how the remaining 8 bits should be shifted
                     * withing a 32 bit window to allow for representing a wider
                     * range of useful values. the problem is that four our translation
                     * from eBPF to ARM we would need an inverse function of that
                     * encoding which given the raw binary immediate that eBPF gives
                     * us, would give use the immediate encoding that would yield the
                     * original immediate value after applying the ThumbExpandImm
                     * to it. We currently don't have it so we spill the immediate
                     * to some register and then use CompareRegister instruction
                     *
                     *
                    let opcode = Thumb32OpcodeEncoding::new(0b10, 0b11011, 0b0);
                    return thumb32::Imm12OneRegEncoding::new(opcode, *rd, *imm as u16).emit(mem);
                    */
                    ThumbInstruction::MoveImmediate {
                        rd: SPILL_REG1,
                        imm: *imm as i32,
                    }
                    .emit_into(mem)?;
                    ThumbInstruction::CompareRegisters {
                        rm: SPILL_REG1,
                        rd: *rd,
                    }
                    .emit_into(mem)
                }
            }
            ThumbInstruction::Add8BitImmediate { rd, imm8 } => {
                const SUB_OPCODE: u8 = 0b110;
                thumb16::Imm8OneRegEncoding::new(BASIC, SUB_OPCODE, *imm8, *rd).emit(mem)
            }
            ThumbInstruction::Subtract8BitImmediate { rd, imm8 } => {
                const SUB_OPCODE: u8 = 0b111;
                thumb16::Imm8OneRegEncoding::new(BASIC, SUB_OPCODE, *imm8, *rd).emit(mem)
            }
            // Data processing (operate mostly on registers)
            ThumbInstruction::BitwiseAND { rm, rd } => {
                const AND_OPCODE: u8 = 0b0000;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, AND_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::ExclusiveOR { rm, rd } => {
                const EOR_OPCODE: u8 = 0b0001;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, EOR_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::LogicalShiftLeft { rm, rd } => {
                const LSL_OPCODE: u8 = 0b0010;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, LSL_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::LogicalShiftRight { rm, rd } => {
                const LSR_OPCODE: u8 = 0b0011;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, LSR_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::ArithmeticShiftRight { rm, rd } => {
                const ASR_OPCODE: u8 = 0b0100;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, ASR_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::AddWithCarry { rm, rd } => {
                const ADC_OPCODE: u8 = 0b0101;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, ADC_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::SubtractWithCarry { rm, rd } => {
                const SBC_OPCODE: u8 = 0b0110;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, SBC_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::RotateRight { rm, rd } => {
                const ROR_OPCODE: u8 = 0b0111;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, ROR_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::SetFlagsOnBitwiseAND { rm, rd } => {
                const TST_OPCODE: u8 = 0b1000;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, TST_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::ReverseSubtractFrom0 { rm, rd } => {
                const RSB_OPCODE: u8 = 0b1001;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, RSB_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::CompareRegisters { rm, rd } => {
                // We use an appropriate encoding depending on the size of
                // registers.
                if *rm < (1 << 3) && *rd < (1 << 3) {
                    const CMP_OPCODE: u8 = 0b1010;
                    return thumb16::TwoRegsEncoding::new(DATA_PROCESSING, CMP_OPCODE, *rm, *rd)
                        .emit(mem);
                } else {
                    const CMP_OPCODE: u8 = 0b01;
                    return thumb16::TwoRegistersSpecialEncoding::new(CMP_OPCODE, *rm, *rd)
                        .emit(mem);
                }
            }
            ThumbInstruction::CompareNegative { rm, rd } => {
                const CMN_OPCODE: u8 = 0b1011;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, CMN_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::LogicalOR { rm, rd } => {
                const ORR_OPCODE: u8 = 0b1100;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, ORR_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::MultiplyTwoRegisters { rm, rd } => {
                const MUL_OPCODE: u8 = 0b1101;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, MUL_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::BitClear { rm, rd } => {
                const BIC_OPCODE: u8 = 0b1110;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, BIC_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::BitwiseNOT { rm, rd } => {
                const MVN_OPCODE: u8 = 0b1111;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, MVN_OPCODE, *rm, *rd).emit(mem)
            }
            // Special data instructions and branch and exchange
            ThumbInstruction::AddRegistersSpecial { rm, rd } => {
                const ADD_OPCODE: u8 = 0b00;
                thumb16::TwoRegistersSpecialEncoding::new(ADD_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::MoveRegistersSpecial { rm, rd } => {
                const MOV_OPCODE: u8 = 0b10;
                thumb16::TwoRegistersSpecialEncoding::new(MOV_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::BranchAndExchange { rm } => {
                const BX_OPCODE: u8 = 0b110;
                thumb16::SpecialBranchEncoding::new(BX_OPCODE, *rm).emit(mem)
            }
            ThumbInstruction::BranchWithLinkAndExchange { rm } => {
                const BLX_OPCODE: u8 = 0b111;
                thumb16::SpecialBranchEncoding::new(BLX_OPCODE, *rm).emit(mem)
            }
            // Load/store single data item
            ThumbInstruction::StoreRegister { rm, rn, rt } => {
                const OP_A: InstructionClassOpcode = InstructionClassOpcode::new(0b0101, 4);
                const STR_OPCODE: u8 = 0b000;
                thumb16::ThreeRegsEncoding::new(OP_A, STR_OPCODE, *rm, *rn, *rt).emit(mem)
            }
            ThumbInstruction::StoreRegisterHalfword { rm, rn, rt } => {
                const OP_A: InstructionClassOpcode = InstructionClassOpcode::new(0b0101, 4);
                const STRH_OPCODE: u8 = 0b001;
                thumb16::ThreeRegsEncoding::new(OP_A, STRH_OPCODE, *rm, *rn, *rt).emit(mem)
            }
            ThumbInstruction::StoreRegisterByte { rm, rn, rt } => {
                const OP_A: InstructionClassOpcode = InstructionClassOpcode::new(0b0101, 4);
                const STRB_OPCODE: u8 = 0b010;
                thumb16::ThreeRegsEncoding::new(OP_A, STRB_OPCODE, *rm, *rn, *rt).emit(mem)
            }
            ThumbInstruction::LoadRegisterSignedByte { rm, rn, rt } => {
                const OP_A: InstructionClassOpcode = InstructionClassOpcode::new(0b0101, 4);
                const LDRSB_OPCODE: u8 = 0b011;
                thumb16::ThreeRegsEncoding::new(OP_A, LDRSB_OPCODE, *rm, *rn, *rt).emit(mem)
            }
            ThumbInstruction::LoadRegister { rm, rn, rt } => {
                const OP_A: InstructionClassOpcode = InstructionClassOpcode::new(0b0101, 4);
                const LDR_OPCODE: u8 = 0b100;
                thumb16::ThreeRegsEncoding::new(OP_A, LDR_OPCODE, *rm, *rn, *rt).emit(mem)
            }
            ThumbInstruction::LoadRegisterHalfword { rm, rn, rt } => {
                const OP_A: InstructionClassOpcode = InstructionClassOpcode::new(0b0101, 4);
                const LDRH_OPCODE: u8 = 0b101;
                thumb16::ThreeRegsEncoding::new(OP_A, LDRH_OPCODE, *rm, *rn, *rt).emit(mem)
            }
            ThumbInstruction::LoadRegisterByte { rm, rn, rt } => {
                const OP_A: InstructionClassOpcode = InstructionClassOpcode::new(0b0101, 4);
                const LDRB_OPCODE: u8 = 0b110;
                thumb16::ThreeRegsEncoding::new(OP_A, LDRB_OPCODE, *rm, *rn, *rt).emit(mem)
            }
            ThumbInstruction::LoadRegisterSignedHalfword { rm, rn, rt } => {
                const OP_A: InstructionClassOpcode = InstructionClassOpcode::new(0b0101, 4);
                const LDRSH_OPCODE: u8 = 0b111;
                thumb16::ThreeRegsEncoding::new(OP_A, LDRSH_OPCODE, *rm, *rn, *rt).emit(mem)
            }
            ThumbInstruction::StoreRegisterImmediate { imm, rn, rt } => {
                // Special case when we do the SP relative store
                if 0 <= *imm && *imm < (1 << 8) && *rn == SP && *rt < (1 << 3) {
                    // If the immediate fits into 8 bits and we load relative to SP we use
                    // the load register SP relative instruction.
                    const OP_A: InstructionClassOpcode = InstructionClassOpcode::new(0b1001, 4);
                    const STR_OPCODE: u8 = 0b0; // Opcode for the SP-relative load
                    return thumb16::Imm8OneRegEncoding::new(OP_A, STR_OPCODE, *imm as u8, *rt)
                        .emit(mem);
                }
                let opcode_t1 =
                    Thumb16OpcodeEncoding::new(InstructionClassOpcode::new(0b0110, 4), 0b0);
                let opcode_t2 = Thumb32OpcodeEncoding::new(0b11, 0b100, 0b0);
                let opcode_t3 = Thumb32OpcodeEncoding::new(0b11, 0b1100, 0b0);
                emit_load_store(mem, imm, rn, rt, opcode_t1, opcode_t2, opcode_t3)
            }
            ThumbInstruction::LoadRegisterImmediate { imm, rn, rt } => {
                // Special case when we do the SP relative load
                if 0 <= *imm && *imm < (1 << 8) && *rn == SP && *rt < (1 << 3) {
                    // If the immediate fits into 8 bits and we load relative to SP we use
                    // the load register SP relative instruction.
                    const OP_A: InstructionClassOpcode = InstructionClassOpcode::new(0b1001, 4);
                    const LDR_OPCODE: u8 = 0b1; // Opcode for the SP-relative load
                    return thumb16::Imm8OneRegEncoding::new(OP_A, LDR_OPCODE, *imm as u8, *rt)
                        .emit(mem);
                }
                let opcode_t1 =
                    Thumb16OpcodeEncoding::new(InstructionClassOpcode::new(0b0110, 4), 0b1);
                let opcode_t2 = Thumb32OpcodeEncoding::new(0b11, 0b101, 0b0);
                let opcode_t3 = Thumb32OpcodeEncoding::new(0b11, 0b1101, 0b0);
                emit_load_store(mem, imm, rn, rt, opcode_t1, opcode_t2, opcode_t3)
            }
            ThumbInstruction::StoreRegisterByteImmediate { imm, rn, rt } => {
                let opcode_t1 =
                    Thumb16OpcodeEncoding::new(InstructionClassOpcode::new(0b0111, 4), 0b0);
                let opcode_t2 = Thumb32OpcodeEncoding::new(0b11, 0b0000, 0b0);
                let opcode_t3 = Thumb32OpcodeEncoding::new(0b11, 0b1000, 0b0);
                emit_load_store(mem, imm, rn, rt, opcode_t1, opcode_t2, opcode_t3)
            }
            ThumbInstruction::LoadRegisterByteImmediate { imm, rn, rt } => {
                let opcode_t1 =
                    Thumb16OpcodeEncoding::new(InstructionClassOpcode::new(0b0111, 4), 0b1);
                let opcode_t2 = Thumb32OpcodeEncoding::new(0b11, 0b0001, 0b0);
                let opcode_t3 = Thumb32OpcodeEncoding::new(0b11, 0b1001, 0b0);
                emit_load_store(mem, imm, rn, rt, opcode_t1, opcode_t2, opcode_t3)
            }
            ThumbInstruction::StoreRegisterHalfwordImmediate { imm, rn, rt } => {
                let opcode_t1 =
                    Thumb16OpcodeEncoding::new(InstructionClassOpcode::new(0b1000, 4), 0b0);
                let opcode_t2 = Thumb32OpcodeEncoding::new(0b11, 0b0010, 0b0);
                let opcode_t3 = Thumb32OpcodeEncoding::new(0b11, 0b1010, 0b0);
                emit_load_store(mem, imm, rn, rt, opcode_t1, opcode_t2, opcode_t3)
            }
            ThumbInstruction::LoadRegisterHalfwordImmediate { imm, rn, rt } => {
                let opcode_t1 =
                    Thumb16OpcodeEncoding::new(InstructionClassOpcode::new(0b1000, 4), 0b0);
                let opcode_t2 = Thumb32OpcodeEncoding::new(0b11, 0b0011, 0b0);
                let opcode_t3 = Thumb32OpcodeEncoding::new(0b11, 0b1011, 0b0);
                emit_load_store(mem, imm, rn, rt, opcode_t1, opcode_t2, opcode_t3)
            }
            // Miscellaneous 16-bit instructions
            ThumbInstruction::AddImmediateToSP { imm } => {
                const ADD_OPCODE: u8 = 0b0;
                thumb16::SPPlusMinusImmediateEncoding::new(ADD_OPCODE, *imm).emit(mem)
            }

            ThumbInstruction::SubtractImmediateFromSP { imm } => {
                const SUBTRACT_OPCODE: u8 = 0b1;
                thumb16::SPPlusMinusImmediateEncoding::new(SUBTRACT_OPCODE, *imm).emit(mem)
            }
            ThumbInstruction::CompareAndBranchOnZero { i, imm5, rn } => {
                thumb16::CompareAndBranchEncoding::new(0b0, *i, *imm5, *rn).emit(mem)
            }
            ThumbInstruction::SignedExtendHalfword { rm, rd } => {
                const STXH_OPCODE: u8 = 0b001000;
                thumb16::TwoRegsEncoding::new(MISCELLANEOUS, STXH_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::SignedExtendByte { rm, rd } => {
                const STXB_OPCODE: u8 = 0b001001;
                thumb16::TwoRegsEncoding::new(MISCELLANEOUS, STXB_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::UnsignedExtendHalfword { rm, rd } => {
                const UTXH_OPCODE: u8 = 0b001010;
                thumb16::TwoRegsEncoding::new(MISCELLANEOUS, UTXH_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::UnsignedExtendByte { rm, rd } => {
                const UTXB_OPCODE: u8 = 0b001011;
                thumb16::TwoRegsEncoding::new(MISCELLANEOUS, UTXB_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::PushMultipleRegisters { registers } => {
                // The shorter encoding only allows for pushing LR and R0-R7
                if registers.iter().filter(|&r| r != &LR).any(|&r| r > 7) {
                    return thumb32::PushMultipleRegsEncoding::new(registers.to_vec()).emit(mem);
                }
                const PUSH_OPCODE: u8 = 0b010;
                let mut reg_list: u8 = 0;
                for reg in registers {
                    if reg != &LR {
                        reg_list |= 1 << reg;
                    }
                }
                let m = if registers.contains(&LR) { 1 } else { 0 };

                thumb16::PushPopEncoding::new(PUSH_OPCODE, m, reg_list).emit(mem)
            }
            ThumbInstruction::ByteReverseWord { rm, rd } => {
                const REV_OPCODE: u8 = 0b101000;
                thumb16::TwoRegsEncoding::new(MISCELLANEOUS, REV_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::ByteReversePackedHalfword { rm, rd } => {
                const REV16_OPCODE: u8 = 0b101001;
                thumb16::TwoRegsEncoding::new(MISCELLANEOUS, REV16_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::ByteReverseSignedHalfword { rm, rd } => {
                const REVSH_OPCODE: u8 = 0b101011;
                thumb16::TwoRegsEncoding::new(MISCELLANEOUS, REVSH_OPCODE, *rm, *rd).emit(mem)
            }
            ThumbInstruction::CompareAndBranchOnNonZero { i, imm5, rn } => {
                thumb16::CompareAndBranchEncoding::new(0b1, *i, *imm5, *rn).emit(mem)
            }
            ThumbInstruction::PopMultipleRegisters { registers } => {
                // The shorter encoding only allows for popping PC and R0-R7
                if registers.iter().filter(|&r| r != &PC).any(|&r| r > 7) {
                    return thumb32::PopMultipleRegsEncoding::new(registers.to_vec()).emit(mem);
                }
                let mut reg_list: u8 = 0;
                for reg in registers {
                    if reg != &PC {
                        reg_list |= 1 << reg;
                    }
                }
                const POP_OPCODE: u8 = 0b110;
                let p = if registers.contains(&PC) { 1 } else { 0 };

                thumb16::PushPopEncoding::new(POP_OPCODE, p, reg_list).emit(mem)
            }
            //ThumbInstruction::Breakpoint => todo!(),
            //ThumbInstruction::IfThen => todo!(),
            //ThumbInstruction::YieldHint => todo!(),
            //ThumbInstruction::WaitForEventHint => todo!(),
            //ThumbInstruction::WaitForInterruptHint => todo!(),
            //ThumbInstruction::SendEventHint => todo!(),
            //ThumbInstruction::SupervisorCall => todo!(),
            ThumbInstruction::ConditionalBranch { cond, imm } => {
                let immediate = *imm;
                // Emit the right encoding depending on the size of the immediate offset.
                let encoding = if -128 < *imm && *imm < 127 {
                    thumb16::ConditionalBranchEncoding::new(*cond, immediate as i8)
                } else {
                    // TODO: replace it with the 32 bit cond branch allowing for
                    // larger jumps.
                    thumb16::ConditionalBranchEncoding::new(*cond, immediate as i8)
                };
                return encoding.emit(mem);
            }
            ThumbInstruction::NoOperationHint => {
                debug!("Emitting no-op hint at {:#x}", mem.offset);
                thumb16::HintEncoding::new(0b0, 0b0).emit(mem)
            }

            ThumbInstruction::CompareRegistersShift {
                rm: _,
                rd: _,
                shift: _,
            } => todo!(),
            ThumbInstruction::SignedDivide { rd, rm, rn } => {
                let opcode = Thumb32OpcodeEncoding::new(0b11, 0b0111001, 0b1);
                thumb32::ThreeRegsEncoding::new(opcode, *rd, *rn, *rm).emit(mem)
            }
            ThumbInstruction::BlankInstruction => {
                emit::<u16>(mem, 0);
                Ok(())
            }
            ThumbInstruction::Add12BitImmediate { imm12, rn, rd } => {
                let opcode = Thumb32OpcodeEncoding::new(0b10, 0b100000, 0b0);
                return thumb32::Imm12SplitTwoRegsEncoding::new(opcode, *rn, *rd, *imm12 as u16)
                    .emit(mem);
            }
            ThumbInstruction::Subtract12BitImmediate { imm12, rn, rd } => {
                let opcode = Thumb32OpcodeEncoding::new(0b10, 0b101010, 0b0);
                return thumb32::Imm12SplitTwoRegsEncoding::new(opcode, *rn, *rd, *imm12 as u16)
                    .emit(mem);
            }
            ThumbInstruction::StoreRegisterSPRelative { rt, imm8 } => {
                thumb16::Imm8OneRegEncoding::new(
                    InstructionClassOpcode::new(0b1001, 4),
                    0b0,
                    *imm8,
                    *rt,
                )
                .emit(mem)
            }
        }
    }
}

/// Encodes load/store immediate instruction appropriately depending on the size
/// of the immediate operand and register numbers. It needs to take in the three
/// opcodes that are used for the three possible variants of the emitted instruction:
/// - T1: 5-bit unsigned immediate and two 3-bit registers -> 16 bit encoding
/// - T2: 8-bit immediate (possibly negative) and two 4-bit registers -> 32 bit encoding
/// - T3: 12-bit immediate and two 4-bit registers -> 32 bit encoding
fn emit_load_store(
    mem: &mut JitMemory,
    imm: &i16,
    rn: &u8,
    rt: &u8,
    opcode_t1: Thumb16OpcodeEncoding,
    opcode_t2: Thumb32OpcodeEncoding,
    opcode_t3: Thumb32OpcodeEncoding,
) -> Result<(), Error> {
    if imm.abs() > (1 << 12) {
        Err(Error::new(
            ErrorKind::Other,
            format!(
                "[JIT] Instruction STR with immediate {:#x} which does not fit into 12 bits.",
                imm
            ),
        ))?;
    }

    // T2: 8-bit immediate (possibly negative) and two 4-bit registers -> 32 bit encoding
    if *imm < 0 && -1 * imm < (1 << 8) {
        let p = 1; // Controlls whether we apply the offset when indexing (offset addressing)
        let u = 0; // Specifies that the offset needs to be subtracted
        let w = 0; // No writeback
        let imm = (-1 * imm) as u8;
        return thumb32::Imm8TwoRegsEncoding::new(opcode_t2, *rn, *rt, p, u, w, imm).emit(mem);
    }

    // T1: 5-bit unsigned immediate and two 3-bit registers -> 16 bit encoding
    if *imm < (1 << 5) && *rn < (1 << 3) && *rt < (1 << 3) {
        return thumb16::Imm5TwoRegsEncoding::new(
            opcode_t1.class_opcode,
            opcode_t1.opcode,
            *imm as u8,
            *rn,
            *rt,
        )
        .emit(mem);
    }

    // T3: catch-all 12-bit immediate and two 4-bit registers -> 32 bit encoding
    return thumb32::Imm12TwoRegsEncoding::new(opcode_t3, *rn, *rt, *imm as u16).emit(mem);
}
