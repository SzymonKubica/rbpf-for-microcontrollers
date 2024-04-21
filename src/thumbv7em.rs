use crate::thumb_16bit_encoding::{
    self as thumb16, Emittable, InstructionClassOpcode, Thumb16OpcodeEncoding, BASIC,
    DATA_PROCESSING, MISCELLANEOUS,
};
use crate::thumb_32bit_encoding::{self as thumb32, Thumb32OpcodeEncoding};
use crate::{jit_thumbv7em::emit, JitMemory};
use log::debug;
use stdlib::collections::Vec;
use stdlib::{Error, ErrorKind, String};

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
    Subtract3BitImmediate {
        imm3: u8,
        rn: u8,
        rd: u8,
    },
    MoveImmediate {
        rd: u8,
        imm: u8,
    },
    CompareImmediate {
        rd: u8,
        imm8: u8,
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
    Compare {
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
    CompareRegistersSpecial {
        rm: u8,
        rd: u8,
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
    // NoOperationHint,
    // YieldHint,
    // WaitForEventHint,
    // WaitForInterruptHint,
    // SendEventHint,
    // Conditional branch and supervisor call
    ConditionalBranch {
        cond: u8,
        imm8: u8,
    },
    //SupervisorCall,
}

impl ThumbInstruction {
    pub fn emit_into(&self, mem: &mut JitMemory) -> Result<(), Error> {
        match self {
            // Shift (immediate), add, subtract, move, and compare
            ThumbInstruction::LogicalShiftLeftImmediate { imm5, rm, rd } => {
                const LSL_OPCODE: u8 = 0b00;
                thumb16::Imm5TwoRegsEncoding::new(BASIC, LSL_OPCODE, *imm5, *rm, *rd).emit(mem)
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
                const MOV_OPCODE: u8 = 0b0100;
                thumb16::Imm8OneRegEncoding::new(BASIC, MOV_OPCODE, *imm, *rd).emit(mem)
            }
            ThumbInstruction::CompareImmediate { rd, imm8 } => {
                const CPM_OPCODE: u8 = 0b0101;
                thumb16::Imm8OneRegEncoding::new(BASIC, CPM_OPCODE, *imm8, *rd).emit(mem)
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
            ThumbInstruction::Compare { rm, rd } => {
                const CMP_OPCODE: u8 = 0b1010;
                thumb16::TwoRegsEncoding::new(DATA_PROCESSING, CMP_OPCODE, *rm, *rd).emit(mem)
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
            ThumbInstruction::CompareRegistersSpecial { rm, rd } => {
                const CMP_OPCODE: u8 = 0b01;
                thumb16::TwoRegistersSpecialEncoding::new(CMP_OPCODE, *rm, *rd).emit(mem)
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
                if *imm < (1 << 8) && *rn == SP && *rt < (1 << 3) {
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
                if *imm < (1 << 8) && *rn == SP && *rt < (1 << 3) {
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
                let opcode_t2 = Thumb32OpcodeEncoding::new(0b11, 0b0010, 0b0);
                let opcode_t3 = Thumb32OpcodeEncoding::new(0b11, 0b1010, 0b0);
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
            //ThumbInstruction::NoOperationHint => todo!(),
            //ThumbInstruction::YieldHint => todo!(),
            //ThumbInstruction::WaitForEventHint => todo!(),
            //ThumbInstruction::WaitForInterruptHint => todo!(),
            //ThumbInstruction::SendEventHint => todo!(),
            //ThumbInstruction::SupervisorCall => todo!(),
            ThumbInstruction::ConditionalBranch { cond, imm8 } => {
                thumb16::ConditionalBranchEncoding::new(*cond, *imm8).emit(mem)
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

    // T3: 12-bit immediate and two 4-bit registers -> 32 bit encoding
    if (1 << 8) <= *imm && *imm < (1 << 12) {
        return thumb32::Imm12TwoRegsEncoding::new(opcode_t3, *rn, *rt, *imm as u16).emit(mem);
    }

    Err(Error::new(
        ErrorKind::Other,
        format!("[JIT] Invalid immediate: {:#x}.", imm),
    ))
}
