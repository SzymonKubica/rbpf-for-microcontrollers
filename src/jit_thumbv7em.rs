// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: JIT algorithm, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (x86 Implementation of JIT, MetaBuff addition)
// Copyright 2024 Szymon Kubica <szymo.kubica@gmail.com>
//      (Adaptation for ARM thumbv7em architecture running on ARM Cortex M4)

use core::mem;
use core::ops::{Index, IndexMut};
use log::debug;
use stdlib::collections::BTreeMap as HashMap;
use stdlib::collections::Vec;
use stdlib::{Error, ErrorKind, String};

use ebpf;
use thumbv7em::*;

use crate::InterpreterVariant;

/// The jit-compiled code can then be called as a function
/// the arguments to this function are as follows:
/// - pointer to the mbuff
/// - mbuff length
/// - pointer to mem
/// - mem length
type MachineCode = unsafe fn(*mut u8, usize, *mut u8, usize) -> u32;

const PAGE_SIZE: usize = 4096;
// TODO: check how long the page must be to be sure to support an eBPF program of maximum possible
// length
const NUM_PAGES: usize = 1;

// Special values for target_pc in struct Jump
const TARGET_OFFSET: isize = ebpf::PROG_MAX_INSNS as isize;
const TARGET_PC_EXIT: isize = TARGET_OFFSET + 1;

#[derive(Copy, Clone)]
enum OperandSize {
    S8 = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

const REGISTER_MAP_SIZE: usize = 11;
// Mapps from the the ARMv7-eM registers to the eBPF registers
// Note that the annotations on the right describe the function of the register
// in the eBPF ISA, which specifies e.g. that SP needs to be the register 10
// whereas in ARMv7-eM it is R13.
const REGISTER_MAP: [u8; REGISTER_MAP_SIZE] = [
    R0, // 0  return value
    R1, // 1  arg 1
    R2, // 2  arg 2
    R3, // 3  arg 3
    R4, // 4  arg 4
    R5, // 5  arg 5
    R6, // 6  callee-saved
    R7, // 7  callee-saved
    R8, // 8  callee-saved
    R9, // 9 callee-saved
    SP, // 10 stack pointer (eBPF specification requires that SP is in register 10)
        // R10 and R11 are used to compute store a constant pointer to mem and to compute offset for
        // LD_ABS_* and LD_IND_* operations, so they are not mapped to any eBPF register.
];

/// The register used by instructions using immediate operands that don't have
/// ARM equivalents. For instance ebpf::MUL_IMM instruction multiplies a value in
/// a given register by an immediate constant, however there is no such instruction
/// in the Thumb ISA used by the Cortex M, because of this, we need to move the
/// immediate constant into some register and then use the instruction which operates
/// on registers. We use this register for that. We need to figure out which registers we
/// should be able to access and will never be explicitly touched by the eBPF code.
pub const SPILL_REG1: u8 = R4;
pub const SPILL_REG2: u8 = R5;

// Return the ARMv7-eM register for the given eBPF register
fn map_register(r: u8) -> u8 {
    assert!(r < REGISTER_MAP_SIZE as u8);
    REGISTER_MAP[(r % REGISTER_MAP_SIZE as u8) as usize]
}

#[inline]
pub fn emit<T>(mem: &mut JitMemory, data: T) {
    unsafe {
        let ptr = mem.contents.as_ptr().add(mem.offset);
        #[allow(clippy::cast_ptr_alignment)]
        core::ptr::write_unaligned(ptr as *mut T, data as T);
    }
    mem.offset += core::mem::size_of::<T>();
}

/// Structure representing a control flow jump. We need it because sometimes
/// translation from eBPF to ARM involves emitting more instructions than there
/// were originally in eBPF bytecode. Because of this we need to adjust jump offsets
/// so that they point to the correct program locations.
#[derive(Debug)]
struct Jump {
    // The index of the 'logical eBPF branch instruction used to recover the actual
    // length of the jump
    insn_ptr: usize,
    // The exact offset in memory where the branch instruction should be written
    memory_offset: usize,
    /// The offset of the jump instruction specifying how long the jump needs
    /// to be in terms of eBPF isntructions (this might mean more actual ARM instructions)
    offset: isize,
    /// Instruction to be written into the program once the memory offset is known.
    condition: Condition,
}

#[derive(Debug)]
pub struct JitCompiler {
    /// Program counter locations in the JIT-compiled code. This is needed
    /// because the translation isn't one-to-one and so sometimes we need to
    /// emit more than one ARM instruction to translate one eBPF instruction,
    /// because of this, we need to store the program counter locations of where
    /// the actual eBPF instructions start so that we can adjust branch offsets
    /// accordingly later on.
    pc_locations: Vec<usize>,
    special_targets: HashMap<isize, usize>,
    jumps: Vec<Jump>,
    /// Specifies the binary laout of the eBPF program code buffer so that the
    /// jit compiler is able to extract the text section from it and start translating
    /// instructions.
    interpreter_variant: InterpreterVariant,
}

/// Type alias for conciseness
type I = ThumbInstruction;

impl JitCompiler {
    pub fn new(interpreter: InterpreterVariant) -> JitCompiler {
        JitCompiler {
            pc_locations: vec![],
            jumps: vec![],
            special_targets: HashMap::new(),
            interpreter_variant: interpreter,
        }
    }
    pub fn jit_compile(
        &mut self,
        mem: &mut JitMemory,
        prog: &[u8],
        use_mbuff: bool,
        update_data_ptr: bool, // This isn't used by my version of the jit.
        helpers: &HashMap<u32, ebpf::Helper>,
    ) -> Result<(), Error> {
        let callee_saved_regs = vec![R4, R5, R6, R7, R8, R10, R11, LR];
        I::PushMultipleRegisters {
            registers: callee_saved_regs.clone(),
        }
        .emit_into(mem)?;

        // According to the ARM calling convention, arguments to the function
        // are passed in registers R0-R3.
        // R0: mbuff
        // R1: mbuff_len
        // R2: mem
        // R3: mem_len

        // Save mem pointer for use with LD_ABS_* and LD_IND_* instructions
        I::MoveRegistersSpecial { rm: R2, rd: R10 }.emit_into(mem)?;

        // We need to adjust pointers to the packet buffer and mem according
        // to the eBPF specification
        if use_mbuff {
            // If we use the mbuff we need to bring the pointer to it into R1
            // The mbuff pointer is the first argument into the jitted function
            // so it will end up in R0
            let rd = map_register(1); // eBPF R1
            if rd != R0 {
                I::MoveRegistersSpecial { rm: R0, rd }.emit_into(mem)?;
            }
        } else {
            // We do not use any mbuff. Move mem pointer into register 1.
            let rd = map_register(1); // eBPF R1
            if rd != R2 {
                I::MoveRegistersSpecial { rm: R2, rd }.emit_into(mem)?;
            }
        }

        // Copy stack pointer to R10
        I::MoveRegistersSpecial {
            rm: SP,
            rd: map_register(10),
        }
        .emit_into(mem);

        // Allocate stack space
        // Subtract eBPF stack size from STACK pointer. Given that our instruction
        // allows for shifting the stack by at most 4*127 bytes at once, we need
        // to do this twice to achieve the stack size of 512 used by eBPF.
        let offset = ebpf::STACK_SIZE as u16 / 2;
        I::SubtractImmediateFromSP { imm: offset }.emit_into(mem)?;
        I::SubtractImmediateFromSP { imm: offset }.emit_into(mem)?;

        self.pc_locations = vec![0; prog.len() / ebpf::INSN_SIZE + 1];

        // Depending on the binary file layout the pointer to the first instruction
        // is located in different places.
        let prog = match self.interpreter_variant {
            InterpreterVariant::Default => prog,
            InterpreterVariant::FemtoContainersHeader => prog,
            InterpreterVariant::ExtendedHeader => prog,
            InterpreterVariant::RawObjectFile => {
                let Ok(binary) = goblin::elf::Elf::parse(prog) else {
                    Err(Error::new(ErrorKind::Other, "Failed to parse ELF binary"))?
                };

                let Ok(text_section) =
                    crate::interpreter_raw_elf_file::extract_section(".text", &binary, prog)
                else {
                    Err(Error::new(ErrorKind::Other, ".text section not found"))?
                };
                text_section
            }
        };

        let mut insn_ptr: usize = 0;
        while insn_ptr * ebpf::INSN_SIZE < prog.len() {
            let insn = ebpf::get_insn(prog, insn_ptr);

            self.pc_locations[insn_ptr] = mem.offset;

            let dst = map_register(insn.dst);
            let src = map_register(insn.src);
            let target_pc = insn_ptr as isize + insn.off as isize + 1;

            debug!("JIT: insn {:?}", insn);

            match insn.opc {
                // BPF_LD class
                // In case of the LD ABS instructions we load the data from an
                // absolute offset relative to the start of the memory buffer
                // that has been made available to the program. This is done by
                // storing the pointer to that memory in R10 and keeping it there.
                // R10 is a constant pointer to mem.
                ebpf::LD_ABS_B => todo!(), //self.emit_load(mem, OperandSize::S8, R10, R0, insn.imm),
                ebpf::LD_ABS_H => todo!(), //self.emit_load(mem, OperandSize::S16, R10, R0, insn.imm),
                ebpf::LD_ABS_W => todo!(), //self.emit_load(mem, OperandSize::S32, R10, R0, insn.imm),
                ebpf::LD_ABS_DW => todo!(), //self.emit_load(mem, OperandSize::S64, R10, R0, insn.imm),
                ebpf::LD_IND_B => todo!(),
                /*{
                    self.emit_mov(mem, R10, R11); // load mem into R11
                    self.emit_alu64(mem, 0x01, src, R11); // add src to R11
                    self.emit_load(mem, OperandSize::S8, R11, R0, insn.imm); // ld R0, mem[src+imm]
                }*/
                ebpf::LD_IND_H => todo!(),
                /*{
                    self.emit_mov(mem, R10, R11); // load mem into R11
                    self.emit_alu64(mem, 0x01, src, R11); // add src to R11
                    self.emit_load(mem, OperandSize::S16, R11, R0, insn.imm); // ld R0, mem[src+imm]
                }*/
                ebpf::LD_IND_W => todo!(),
                /*{
                    self.emit_mov(mem, R10, R11); // load mem into R11
                    self.emit_alu64(mem, 0x01, src, R11); // add src to R11
                    self.emit_load(mem, OperandSize::S32, R11, R0, insn.imm); // ld R0, mem[src+imm]
                }*/
                ebpf::LD_IND_DW => todo!(),
                /*{
                    self.emit_mov(mem, R10, R11); // load mem into R11
                    self.emit_alu64(mem, 0x01, src, R11); // add src to R11
                    self.emit_load(mem, OperandSize::S64, R11, R0, insn.imm); // ld R0, mem[src+imm]
                }*/
                ebpf::LD_DW_IMM => {
                    // Here in case of lddw, even though eBPF specifies a load of
                    // a 64 bit immediate, we cannot do this as our architecture is only 32 bit
                    // long. Since the top 32 bits of the immediate are located in
                    // the second part of the long lddw instruction, we can extract the
                    // 32 bits that we care about directly from the immediate. We need
                    //  to increase the instruction pointer to skip the second part of the
                    //  instruction.
                    insn_ptr += 1;
                    I::MoveImmediate { rd: dst, imm: insn.imm as i32}.emit_into(mem)?;
                }
                /*{
                    insn_ptr += 1;
                    let second_part = ebpf::get_insn(prog, insn_ptr).imm as u64;
                    let imm = (insn.imm as u32) as u64 | second_part.wrapping_shl(32);
                    self.emit_load_imm(mem, dst, imm as i64);
                }*/

                // BPF_LDX class
                ebpf::LD_B_REG => I::LoadRegisterByteImmediate { imm: insn.off, rn: src, rt: dst }.emit_into(mem)?,
                ebpf::LD_H_REG => I::LoadRegisterHalfwordImmediate { imm: insn.off, rn: src, rt: dst }.emit_into(mem)?,
                ebpf::LD_W_REG =>  I::LoadRegisterImmediate  { imm: insn.off, rn: src, rt: dst }.emit_into(mem)?,
                ebpf::LD_DW_REG => error_32_bit_arch()?,
                // BPF_ST class
                ebpf::ST_B_IMM => {
                    // The ARM ISA does not support storing immediates into memory
                    // We need to load it into a spill register instead and then store it.
                    I::MoveImmediate { rd: SPILL_REG1, imm: insn.imm }.emit_into(mem)?;
                    I::StoreRegisterByteImmediate { imm: insn.off, rn: dst, rt: SPILL_REG1 }.emit_into(mem)?

                }
                ebpf::ST_H_IMM =>  {
                    I::MoveImmediate { rd: SPILL_REG1, imm: insn.imm }.emit_into(mem)?;
                    I::StoreRegisterHalfwordImmediate { imm: insn.off, rn: dst, rt: SPILL_REG1 }.emit_into(mem)?

                }
                ebpf::ST_W_IMM => {
                    I::MoveImmediate { rd: SPILL_REG1, imm: insn.imm }.emit_into(mem)?;
                    I::StoreRegisterImmediate { imm: insn.off, rn: dst, rt: SPILL_REG1 }.emit_into(mem)?
                }
                ebpf::ST_DW_IMM =>  error_32_bit_arch()?,
                // BPF_STX class
                ebpf::ST_B_REG => I::StoreRegisterByteImmediate { imm: insn.off, rn: dst, rt: src }.emit_into(mem)?,
                ebpf::ST_H_REG => I::StoreRegisterHalfwordImmediate { imm: insn.off, rn: dst, rt: src }.emit_into(mem)?,
                ebpf::ST_W_REG => I::StoreRegisterImmediate { imm: insn.off, rn: dst, rt: src }.emit_into(mem)?,
                ebpf::ST_DW_REG => error_32_bit_arch()?,
                ebpf::ST_W_XADD => unimplemented!(),
                ebpf::ST_DW_XADD => unimplemented!(),

                // BPF_ALU and BPF_ALU64 classes, we treat both of them in the
                // same way as our architecture is 32bit
                ebpf::ADD32_IMM | ebpf::ADD64_IMM => {
                    // Given that we are running on a 32 bit architecture, we treat
                    // both 32 and 64 bit instructions the same but fail to jit if the operand
                    // doesn't fit into 32 bits.
                    if insn.imm >> 8 > 0 {
                        Err(Error::new(
                            ErrorKind::Other,
                            format!(
                                "[JIT] Instruction with immediate {:#x} which does not fit into 8 bits.",
                                insn.imm
                            ),
                        ))?;
                    }

                    // The compiler sometimes emits add with negative immediates
                    // se we need to handle it here:
                    if insn.imm < 0 {
                        let imm = -1 * insn.imm;
                        I::Subtract8BitImmediate { rd: dst, imm8: imm as u8 }.emit_into(mem)?;
                    } else {
                        // TODO: make add pick the right instruction based on the size
                        // of the immediate and register numbers.
                        I::Add8BitImmediate { rd: dst, imm8: insn.imm as u8 }.emit_into(mem)?;
                    }
                }
                ebpf::ADD32_REG | ebpf::ADD64_REG => {
                    I::AddRegistersSpecial { rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::SUB32_IMM | ebpf::SUB64_IMM => {
                    if insn.imm >> 8 > 0 {
                        Err(Error::new(
                            ErrorKind::Other,
                            format!(
                                "[JIT] Instruction with immediate {:#x} which does not fit into 8 bits.",
                                insn.imm
                            ),
                        ))?;
                    }
                    I::Subtract8BitImmediate { rd: dst, imm8: insn.imm as u8 }.emit_into(mem)?;
                }
                ebpf::SUB32_REG | ebpf::SUB64_REG => {
                    I::Subtract { rm: insn.src, rn: insn.dst, rd: insn.dst } .emit_into(mem)?;
                }
                ebpf::MUL32_IMM | ebpf::MUL64_IMM => {
                    // The ARMv7-eM architecture does not support multiplication with an immediate
                    // we need to move the value into some register and then perform
                    // multiplication.
                    // We could use R11 for it as it isn't used by the eBPF ISA, so it is
                    // guaranteed to not hold any important information.
                    //
                    // Problem: right now we can only move into registers from range R0-R7,
                    // so we store the value in R4 (SPILL_REG) and hope we didn't overwrite anything
                    // TODO: implement the move instruction for larger encodings
                    // and then use it here to move the immediate into R11
                    I::MoveImmediate { rd: SPILL_REG1, imm: insn.imm }.emit_into(mem)?;
                    I::MultiplyTwoRegisters { rm: SPILL_REG1, rd: dst }.emit_into(mem)?;
                }
                ebpf::MUL32_REG | ebpf::MUL64_REG => {
                    I::MultiplyTwoRegisters { rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::DIV32_IMM | ebpf::DIV64_IMM => {
                    I::MoveImmediate { rd: SPILL_REG1, imm: insn.imm }.emit_into(mem)?;
                    I::SignedDivide { rd: dst, rm: SPILL_REG1, rn: dst }.emit_into(mem)?;
                }
                ebpf::DIV32_REG | ebpf::DIV64_REG => {
                    I::SignedDivide { rd: dst, rm: src, rn: dst }.emit_into(mem)?;
                }
                ebpf::MOD32_IMM | ebpf::MOD64_IMM => {
                    // Armv7-eM does not support modulo instructions, we need to
                    // get around that by performing a signed division and then subtracting the
                    // result times the divisor from the original value of the register, i.e.:
                    // x % y = x - y * (x / y)
                    I::MoveImmediate { rd: SPILL_REG1, imm: insn.imm }.emit_into(mem)?;
                    I::SignedDivide { rd: SPILL_REG2, rm: SPILL_REG1, rn: dst }.emit_into(mem)?;
                    I::MultiplyTwoRegisters { rm: SPILL_REG1, rd: SPILL_REG2 }.emit_into(mem)?;
                    I::Subtract { rm: SPILL_REG2, rn: dst, rd: dst }.emit_into(mem)?;
                }
                ebpf::MOD32_REG | ebpf::MOD64_REG => {
                    // We need to work around the mod as above
                    I::SignedDivide { rd: SPILL_REG2, rm: src, rn: dst }.emit_into(mem)?;
                    I::MultiplyTwoRegisters { rm: src, rd: SPILL_REG2 }.emit_into(mem)?;
                    I::Subtract { rm: SPILL_REG2, rn: dst, rd: dst }.emit_into(mem)?;
                }
                ebpf::OR32_IMM | ebpf::OR64_IMM => {
                    I::MoveImmediate { rd: SPILL_REG1, imm: insn.imm }.emit_into(mem)?;
                    I::LogicalOR { rm: SPILL_REG1, rd: dst }.emit_into(mem)?;
                }
                ebpf::OR32_REG | ebpf::OR64_REG => {
                    I::LogicalOR { rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::AND32_IMM | ebpf::AND64_IMM => {
                    I::MoveImmediate { rd: SPILL_REG1, imm: insn.imm }.emit_into(mem)?;
                    I::BitwiseAND { rm: SPILL_REG1, rd: dst }.emit_into(mem)?;
                }
                ebpf::AND32_REG | ebpf::AND64_REG => {
                    I::BitwiseAND { rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::LSH32_IMM | ebpf::LSH64_IMM => {
                    // For some reason the compiled eBPF does some weird lsl lsr
                    // manipulations whereby they shift a register value by 32 left
                    // and then immediately after by 32 right. The problem is that
                    // this causes our 32 bit registers to overflow and essentially
                    // flushes the value. I noticed the compiler doing those things
                    // before comparisons of 32 bit numbers so I suspect the reason
                    // those instructions are there is to effectively drop the highest
                    // 32 bits so that we can do a comparison on the lower 32 bits.
                    //
                    // Workaound: if an lsl is requested for 32, we emit a noop.
                    if insn.imm == 32 {
                        I::NoOperationHint.emit_into(mem)?;
                    } else {
                        I::LogicalShiftLeftImmediate { imm5: insn.imm as u8, rm: dst, rd: dst }.emit_into(mem)?;
                    }
                }
                ebpf::LSH32_REG | ebpf::LSH64_REG => {
                    I::LogicalShiftLeft { rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::RSH32_IMM | ebpf::RSH64_IMM => {
                    if insn.imm == 32 {
                        I::NoOperationHint.emit_into(mem)?;
                    } else {
                        I::LogicalShiftRightImmediate { imm5: insn.imm as u8, rm: dst, rd: dst }.emit_into(mem)?;
                    }
                }
                ebpf::RSH32_REG | ebpf::RSH64_REG => {
                    I::LogicalShiftRight { rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::NEG32 | ebpf::NEG64 => {
                    I::BitwiseNOT { rm: dst, rd: dst }.emit_into(mem)?;
                }
                ebpf::XOR32_IMM | ebpf::XOR64_IMM => {
                    I::MoveImmediate { rd: SPILL_REG1, imm: insn.imm }.emit_into(mem)?;
                    I::ExclusiveOR  { rm: SPILL_REG1, rd: dst }.emit_into(mem)?;
                }
                ebpf::XOR32_REG | ebpf::XOR64_REG => {
                    I::ExclusiveOR { rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::MOV32_IMM | ebpf::MOV64_IMM => {
                    I::MoveImmediate { rd: dst, imm: insn.imm}.emit_into(mem)?;
                }
                ebpf::MOV32_REG | ebpf::MOV64_REG => {
                    I::MoveRegistersSpecial { rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::ARSH32_IMM | ebpf::ARSH64_IMM => {
                    I::ArithmeticShiftRightImmediate { imm5: insn.imm as u8, rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::ARSH32_REG | ebpf::ARSH64_REG => {
                    I::ArithmeticShiftRight { rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::LE => {} // No-op
                ebpf::BE => todo!(),/*{
                    match insn.imm {
                        16 => {
                            // rol
                            self.emit1(mem, 0x66); // 16-bit override
                            self.emit_alu32_imm8(mem, 0xc1, 0, dst, 8);
                            // and
                            self.emit_alu32_imm32(mem, 0x81, 4, dst, 0xffff);
                        }
                        32 | 64 => {
                            // bswap
                            let bit = match insn.imm {
                                64 => 1,
                                _ => 0,
                            };
                            self.emit_basic_rex(mem, bit, 0, dst);
                            self.emit1(mem, 0x0f);
                            self.emit1(mem, 0xc8 | (dst & 0b111));
                        }
                        _ => unreachable!(), // Should have been caught by verifier
                    }
                }*/
                // BPF_JMP and BPF_JMP32 class (because we can only handle 32 bit
                // values in the registers) the behaviour of both classes is the same.
                ebpf::JA => {
                    // Arm doesn't support condition ALL in the short jump instruction
                    // encoding. Because of this, we comapre the dst register to
                    // itself and branch on equality.
                    I::CompareRegisters { rm: dst, rd: dst }.emit_into(mem)?;
                    // Instead of emitting the branch instruction we store it in the
                    // list of jumps to be written into memory once the offsets are
                    // resolved. Instead we emit a noop instruction so that we have
                    // a blank spot to fill in later
                    self.record_cond_branch(insn_ptr, insn.off, Condition::EQ, mem);

                    // We insert two noops for the branch instruction so that
                    // we can place the actual branch instruction in a way that
                    // ensures that the jumped offset is even.
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JEQ_IMM | ebpf::JEQ_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::EQ, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JEQ_REG | ebpf::JEQ_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::EQ, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JGT_IMM | ebpf::JGT_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::HI, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JGT_REG | ebpf::JGT_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::HI, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JGE_IMM | ebpf::JGE_IMM32 => {
                    // ARM ISA only has LS and HI unsigned comparison condtions,
                    // they mean: LS -> unsigned lower or same
                    //            HI -> unsigned higher
                    // Because of this we cannot directly translate the unsigned
                    // GE and LT in eBPF, rather we need to flip the order of
                    // comparison and use the opposite condition as follows:
                    // GE x, y -> compare y, x  and use LS condition
                    // LT x, y -> compare y, x and use the HI condition.
                    // The problem is that we cannot filp the order when comparing
                    // with immediate, thus we need to load it into a register
                    //
                    // We use GE for now: TODO implement the above if breaks.
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::GE, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JGE_REG | ebpf::JGE_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::GE, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JLT_IMM | ebpf::JLT_IMM32 => {
                    // Note: JLT wants to use an unsigned comparison but our LT is signed -> how to
                    // get around this? Can we repurpose the Condition::HI and reordering operands?
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::LT, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JLT_REG | ebpf::JLT_REG32 => {
                    // We need to handle unsigned LT in as special way as ARM ISA
                    // doesn't provide that condition (we only have LS) which
                    // is unsigned Lower or Same.
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::LT, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JLE_IMM | ebpf::JLE_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::LS, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JLE_REG | ebpf::JLE_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::LS, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }

                ebpf::JSET_IMM | ebpf::JSET_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::CS, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JSET_REG | ebpf::JSET_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::CS, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JNE_IMM | ebpf::JNE_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::NE, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JNE_REG | ebpf::JNE_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::NE, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JSGT_IMM | ebpf::JSGT_IMM32 =>{
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::GT, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JSGT_REG | ebpf::JSGT_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::GT, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JSGE_IMM | ebpf::JSGE_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::GE, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JSGE_REG | ebpf::JSGE_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::GE, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JSLT_IMM | ebpf::JSLT_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::LT, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JSLT_REG | ebpf::JSLT_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::LT, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JSLE_IMM | ebpf::JSLE_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::LE, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }
                ebpf::JSLE_REG | ebpf::JSLE_REG32 =>{
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    self.record_cond_branch(insn_ptr, insn.off, Condition::LE, mem);
                    ThumbInstruction::BlankInstruction.emit_into(mem);
                }

                ebpf::CALL => {
                    // For JIT, helpers in use MUST be registered at compile time. They can be
                    // updated later, but not created after compiling (we need the address of the
                    // helper function in the JIT-compiled program).
                    if let Some(helper) = helpers.get(&(insn.imm as u32)) {

                        // Note: when calling a function, the first four words
                        // of the argument list are passed in registers R0-R3
                        // This is different from eBPF where the first argument
                        // ends up in R1, because of this, we need to shuffle
                        // registers around so that the function that we call can
                        // interpret them correctly. The signature of all helper
                        // functions is the following: fn(u64, u64, u64, u64, u64) -> u64
                        // Given that ARMv7-eM is a 32-bit architecture, the lower
                        // word of the first argument is expected to be in R0,
                        // and the higher one in R1, similarly for the second
                        // argument, the lower part of the double-word is
                        // stored in R2, whereas the higher word ends up in R3.
                        // The remaining arguments should be stored in the stack.
                        //
                        // Given that the eBPF bytecode follows the eBPF calling
                        // convention (where the arguments are stored in R1-R5)
                        // and we are only dealing with 32-bit values, we need to
                        // move the value of R1 into R0 and spill the other registers
                        // R3-R5 onto the stack (R2 is already in its correct place)
                        //
                        // Note that this approach is wasteful in that we aren't using
                        // R1 or R3 as they were supposed to store the upper bits
                        // of u64 values that we aren't using as we only have u32s.
                        // We also need to remember to zero the values of those
                        // registers so that the caller doesn't get confused by some
                        // leftover bits in those regs.
                        //
                        // This could be improved by changing the signature of all
                        // helper functions to fn(u32, u32, u32, u32, u32) -> u32
                        // However that would limit functionality supported by
                        // the interpreted execution which we don't want.
                        //
                        // The motivation is that when using the interpreter we
                        // should aim at highest possible compatibility, whereas
                        // when using the jit we can sacrifice some compatibility
                        // (using u64 value) to gain performance.

                        I::MoveRegistersSpecial { rm: R1, rd: R0 }.emit_into(mem)?;
                        // Clear R1
                        I::MoveImmediate { rd: R1, imm: 0  }.emit_into(mem)?;
                        // R2 already contains the correct value.
                        // We should move R3-R5 to the stack before clearing R3,
                        // however we don't do that yet as we don't need to
                        // support helpers with more than 2 arguments right now.
                        // Clear R3
                        I::MoveImmediate { rd: R3, imm: 0  }.emit_into(mem)?;

                        let mut helper_addr = *helper as u32;
                        // We set the ARM Thumb instruction set selection bit so
                        // that the CPU knows that we aren't trying to change the instruction set.
                        helper_addr |= 0b1;

                        I::MoveImmediate { rd: SPILL_REG1, imm: helper_addr as i32 }.emit_into(mem)?;
                        // Important: BLX destroys the contents of the LR register
                        // (because the called functions needs LR to know where to
                        // return to). Because of this, we need to preserve the contents
                        // of LR across function call by pushing it onto the stack
                        // before the call and then popping it afterwards
                        let registers = vec![LR];
                        I::PushMultipleRegisters { registers: registers.clone()  }.emit_into(mem)?;
                        I::BranchWithLinkAndExchange { rm: SPILL_REG1 }.emit_into(mem)?;
                        I::PopMultipleRegisters { registers  }.emit_into(mem)?;
                    } else {
                        Err(Error::new(
                            ErrorKind::Other,
                            format!(
                                "[JIT] Error: unknown helper function (id: {:#x})",
                                insn.imm as u32
                            ),
                        ))?;
                    };
                }
                ebpf::TAIL_CALL => {
                    unimplemented!()
                }
                ebpf::EXIT => {
                    if insn_ptr != prog.len() / ebpf::INSN_SIZE - 1 {
                        I::BranchAndExchange { rm: LR }.emit_into(mem)?;
                    };
                }

                _ => {
                    Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "[JIT] Error: unknown eBPF opcode {:#2x} (insn #{insn_ptr:?})",
                            insn.opc
                        ),
                    ))?;
                }
            }

            insn_ptr += 1;
        }

        // Epilogue
        //self.set_anchor(mem, TARGET_PC_EXIT);

        // Move register 0 into R0
        if map_register(0) != R0 {
            I::MoveRegistersSpecial {
                rm: map_register(0),
                rd: R0,
            }
            .emit_into(mem)?;
        }

        // Deallocate stack space
        // The add immediate to SP instruction allows for at most 4*127 bytes
        // being shifted, so we need to do this twice to shift the stack by 512 bytes.
        let offset = ebpf::STACK_SIZE as u16 / 2;
        I::AddImmediateToSP { imm: offset }.emit_into(mem)?;
        I::AddImmediateToSP { imm: offset }.emit_into(mem)?;

        I::PopMultipleRegisters {
            registers: callee_saved_regs.clone(),
        }
        .emit_into(mem)?;

        I::BranchAndExchange { rm: LR }.emit_into(mem)?;

        Ok(())
    }

    /// Record a conditional branch instruction for later resolution once the
    /// actual offset is known.
    fn record_cond_branch(
        &mut self,
        insn_ptr: usize,
        jump_offset: i16,
        condition: Condition,
        mem: &mut JitMemory,
    ) {
        let jump = Jump {
            insn_ptr,
            memory_offset: mem.offset,
            offset: jump_offset as isize,
            condition,
        };
        self.jumps.push(jump);
    }

    fn resolve_jumps(&mut self, mem: &mut JitMemory) -> Result<(), Error> {
        for jump in &self.jumps {
            debug!("Resolving jump {:?}", jump);

            // For each of the jump instructions we need to adjust the instruction offset
            // so that it accounts for the previously emitted instructions (it could be that
            // during the translation from eBPF to ARM we have emitted more instructions than
            // the jump offset in the branch instrucition originally accounted for.
            // Because of this we compute the actual jump offset using the following approach:
            // 1. We have stored the original location of the jump instruction in the `jump_start_loc`
            // 2. We have also stored the original intended offset as specified by the eBPF
            //    instruction
            // 3. We can recover the actuall offset using the `self.pc_locations`
            //    which store the actual start address of each 'logical' eBPF instruction
            //    in the jitted program buffer. The reason I refer to this as 'logical'
            //    is that a single eBPF instruction might require multiple ARM instructions
            //    to handle it.
            // 4. Given all of the above information, the actual jump offset in terms of the
            //    number of ARM assembly instructions will be given by:
            debug!("Jump start location: {:#x}", jump.memory_offset);
            // We add 1 here because a jump of 1 in eBPF skips one instruction and so
            // it actually jumps 2 down, similarly a jump of -9 goes up by 8 instructions
            let target_offset = self.pc_locations[(jump.insn_ptr as isize + jump.offset) as usize];
            debug!("Jump target location: {:#x}", target_offset);
            debug!("eBPF Jump offset: ({}) {:#x}", jump.offset, jump.offset);
            // Offsets are in terms of number of bytes in the jit program memory buffer,
            // since the base instruction is 2 bytes we divide by 2
            let actual_offset = (target_offset as isize - jump.memory_offset as isize) / 2;
            debug!("ARM Jump offset: ({}) {:#x}", actual_offset, actual_offset);

            debug!("Writing instruction at offset: {:#x} ", jump.memory_offset);
            let mut offset_mem = JitMemory {
                contents: mem.contents,
                offset: jump.memory_offset,
            };
            ThumbInstruction::ConditionalBranch {
                cond: jump.condition,
                imm: actual_offset as i32,
            }
            .emit_into(&mut offset_mem)?;
        }
        Ok(())
    }

    fn save_callee_save_registers(mem: &mut JitMemory) -> Result<(), Error> {
        let registers = vec![R4, R5, R6, R7, LR];
        I::PushMultipleRegisters { registers }.emit_into(mem)?;

        // We also need to manually push R8, R10 and R11 as they cannot be pushed using push
        // multiple instruction. We do this by first shifting the stack 3 slots downwards and then
        // storing the registers in the newly freed slots. Each entry on the stack occupies 4B
        // The problem is that store register immediate can only take in registers
        // with 3-bit indices, therefore we need to first move R8, R10 and R11 to R4, R5 and R6
        // We can do this as they have already been saved on the stack.
        I::MoveRegistersSpecial { rm: R8, rd: R4 }.emit_into(mem)?;
        I::MoveRegistersSpecial { rm: R10, rd: R5 }.emit_into(mem)?;
        I::MoveRegistersSpecial { rm: R11, rd: R6 }.emit_into(mem)?;

        I::SubtractImmediateFromSP { imm: 12 }.emit_into(mem)?;
        let mut imm = 0;
        let rn = SP;
        I::StoreRegisterImmediate { imm, rn, rt: R4 }.emit_into(mem)?;
        imm += 4;
        I::StoreRegisterImmediate { imm, rn, rt: R5 }.emit_into(mem)?;
        imm += 4;
        I::StoreRegisterImmediate { imm, rn, rt: R6 }.emit_into(mem)
    }

    fn restore_callee_save_registers(mem: &mut JitMemory) -> Result<(), Error> {
        let mut imm = 0;
        let rn = SP;
        I::LoadRegisterImmediate { imm, rn, rt: R4 }.emit_into(mem)?;
        imm += 4;
        I::LoadRegisterImmediate { imm, rn, rt: R5 }.emit_into(mem)?;
        imm += 4;
        I::LoadRegisterImmediate { imm, rn, rt: R6 }.emit_into(mem)?;
        I::AddImmediateToSP { imm: 12 }.emit_into(mem)?;

        I::MoveRegistersSpecial { rm: R4, rd: R8 }.emit_into(mem)?;
        I::MoveRegistersSpecial { rm: R5, rd: R10 }.emit_into(mem)?;
        I::MoveRegistersSpecial { rm: R6, rd: R11 }.emit_into(mem)?;

        // Restore callee-saved registers
        let registers = vec![R4, R5, R6, R7, PC];
        I::PopMultipleRegisters { registers }.emit_into(mem)
    }

    /// Verifies that a given immediate value fits into a bitstring of length
    /// `size`.
    fn verify_immediate_size(imm: i32, size: usize) -> Result<(), Error> {
        if imm > (1 << size) {
            Err(Error::new(
                ErrorKind::Other,
                format!(
                    "[JIT] Immediate {:#x} does not fit into {} bits.",
                    imm, size
                ),
            ))?;
        }
        Ok(())
    }

    /// Verifies that a given offset value fits into a bitstring of length
    /// `size`.
    fn verify_offset_size(off: i16, size: usize) -> Result<(), Error> {
        if off > (1 << size) {
            Err(Error::new(
                ErrorKind::Other,
                format!("[JIT] Offset {:#x} does not fit into {} bits.", off, size),
            ))?;
        }
        Ok(())
    }

    /// Some instructions only support registers in range R0-R7 because they
    /// use 3 bits to specify the register number. Because of this, before
    /// calling those functions we need to verify that the `src` and `dst` values
    /// fit into 3 bits.
    fn verify_register_low(reg: u8) -> Result<(), Error> {
        if reg > 0b111 {
            Err(Error::new(
                ErrorKind::Other,
                format!("[JIT] Register {} does not fit into 3 bits.", reg),
            ))?;
        }
        Ok(())
    }
} // impl JitCompiler

/// Memory storing the JIT compiled program. Because we are planning to use it
/// inside of RIOT, we take in an already intialized memory buffer then initialising
/// the struct.
pub struct JitMemory<'a> {
    contents: &'a mut [u8],
    pub offset: usize,
}

impl<'a> JitMemory<'a> {
    /// It is very important that the `jit_memory_buff` that is passed in here
    /// as an argument is aligned at the 4-byte boundary. This is because the
    /// CPU expects that. One can achieve this by creating a wrapper struct like
    /// this:
    /// ```
    /// #[repr(C, align(4))]
    /// struct AlignedBuffer([u8; 6]);
    /// ```
    /// And then passing a reference to the contents of that struct to this function.
    pub fn new(
        prog: &[u8],
        jit_memory_buff: &'a mut [u8],
        helpers: &HashMap<u32, ebpf::Helper>,
        use_mbuff: bool,
        update_data_ptr: bool,
        interpreter_variant: InterpreterVariant,
    ) -> Result<JitMemory<'a>, Error> {
        let mut mem = JitMemory {
            contents: jit_memory_buff,
            offset: 0,
        };

        let mut jit = JitCompiler::new(interpreter_variant);
        jit.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
        jit.resolve_jumps(&mut mem)?;

        Ok(mem)
    }

    /// Responsible for transmuting the pointer to the jit program memory buffer
    /// so that it can be executed as a funtion. According to the ARM documentation,
    /// the LSB bit of the instruction pointer needs to be set to indicate to the
    /// CPU that it needs to be run in Thumb mode [see here](https://developer.arm.com/documentation/dui0471/m/interworking-arm-and-thumb/pointers-to-functions-in-thumb-state)
    pub fn get_prog(&self) -> MachineCode {
        let mut prog_ptr: u32 = self.contents.as_ptr() as u32;
        let mut prog_str: String = String::new();
        for (i, b) in self.contents.iter().take(self.offset).enumerate() {
            prog_str.push_str(&format!("{:02x}", *b));
            if i % 4 == 3 {
                prog_str.push_str("\n");
            }
        }
        debug!("JIT program:\n{}", prog_str);
        // We need to set the LSB thumb bit.
        prog_ptr = prog_ptr | 0x1;
        unsafe { mem::transmute(prog_ptr as *mut u32) }
    }
}

impl<'a> Index<usize> for JitMemory<'a> {
    type Output = u8;

    fn index(&self, _index: usize) -> &u8 {
        &self.contents[_index]
    }
}

impl<'a> IndexMut<usize> for JitMemory<'a> {
    fn index_mut(&mut self, _index: usize) -> &mut u8 {
        &mut self.contents[_index]
    }
}

/*
impl<'a> std::fmt::Debug for JitMemory<'a> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), FormatterError> {
        fmt.write_str("JIT contents: [")?;
        fmt.write_str(" ] | ")?;
        fmt.debug_struct("JIT memory")
            .field("offset", &self.offset)
            .finish()
    }
}
*/

fn error_32_bit_arch() -> Result<(), Error> {
    Err(Error::new(
        ErrorKind::Other,
        format!(
            "[JIT] Attempted to compile a 64-bit instruction on a 32-bit ARMv7-eM architecture."
        ),
    ))
}
