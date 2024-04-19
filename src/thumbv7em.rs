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
    AddImmediatetoSPADD,
    SubtractImmediatefromSPSUB,
    CompareAndBranchOnZero,
    SignedExtendHalfwordSXTHon,
    SignedExtendByteSXTBon,
    UnsignedExtendHalfwordUXTHon,
    UnsignedExtendByteUXTBon,
    PushMultipleRegistersPUSHon,
    ByteReverseWord,
    ByteReversePackedHalfword,
    ByteReverseSignedHalfword,
    CompareAndBranchOnNonZero,
    PopMultipleRegisters,
    Breakpoint,
    IfThen,
    NoOperationHint,
    YieldHint,
    WaitForEventHint,
    WaitForInterruptHint,
    SendEventHint,
    ConditionalBranch,
    SupervisorCall,
}
