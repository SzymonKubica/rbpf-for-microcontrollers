// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: JIT algorithm, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (x86 Implementation of JIT, MetaBuff addition)
// Copyright 2024 Szymon Kubica <szymo.kubica@gmail.com>
//      (Adaptation for ARM thumbv7em architecture running on ARM Cortex M4)

use alloc::string::ToString;
use core::mem;
use core::ops::{Index, IndexMut};
use log::debug;
use stdlib::collections::BTreeMap as HashMap;
use stdlib::collections::Vec;
use stdlib::{Error, ErrorKind, String};

use ebpf;
use thumbv7em::*;

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
/// on registers. We use this register for that.
const SPILL_REG1: u8 = R3;
const SPILL_REG2: u8 = R4;

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

#[derive(Debug)]
struct Jump {
    offset_loc: usize,
    target_pc: isize,
}

#[derive(Debug)]
pub struct JitCompiler {
    pc_locs: Vec<usize>,
    special_targets: HashMap<isize, usize>,
    jumps: Vec<Jump>,
}

/// Type alias for conciseness
type I = ThumbInstruction;

impl JitCompiler {
    pub fn new() -> JitCompiler {
        JitCompiler {
            pc_locs: vec![],
            jumps: vec![],
            special_targets: HashMap::new(),
        }
    }

    // This is supposed to allow us to jump back to LR.
    fn emit_b(&mut self, mem: &mut JitMemory, reg: u8) {
        let template: u16 = 0b0100011100000000;
        emit::<u16>(mem, template | ((reg & 0b1111) << 3) as u16);
    }

    fn emit_mov_imm8(&self, mem: &mut JitMemory, imm: u8, dst: u8) {
        let template: u16 = 0b00100 << 11;
        emit::<u16>(mem, template | ((dst as u16) << 8) | imm as u16);
    }

    pub fn jit_compile(
        &mut self,
        mem: &mut JitMemory,
        prog: &[u8],
        use_mbuff: bool,
        update_data_ptr: bool, // This isn't used by my version of the jit.
        helpers: &HashMap<u32, ebpf::Helper>,
    ) -> Result<(), Error> {
        Self::save_callee_save_registers(mem)?;

        // According to the ARM calling convention, arguments to the function
        // are passed in registers R0-R3.
        // R0: mbuff
        // R1: mbuff_len
        // R2: mem
        // R3: mem_len

        // Save mem pointer for use with LD_ABS_* and LD_IND_* instructions
        //self.emit_mov(mem, R2, R10);
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

        self.pc_locs = vec![0; prog.len() / ebpf::INSN_SIZE + 1];

        let mut insn_ptr: usize = 0;
        while insn_ptr * ebpf::INSN_SIZE < prog.len() {
            let insn = ebpf::get_insn(prog, insn_ptr);

            self.pc_locs[insn_ptr] = mem.offset;

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
                ebpf::LD_DW_IMM => todo!(),
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
                    // The ARM ISA does not support storing immediates into memory
                    // We need to load it into a spill register instead and then store it.
                    I::MoveImmediate { rd: SPILL_REG1, imm: insn.imm }.emit_into(mem)?;
                    I::StoreRegisterHalfwordImmediate { imm: insn.off, rn: dst, rt: SPILL_REG1 }.emit_into(mem)?

                }
                ebpf::ST_W_IMM => {
                    // The ARM ISA does not support storing immediates into memory
                    // We need to load it into a spill register instead and then store it.
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
                ebpf::DIV32_IMM | ebpf::DIV64_IMM => todo!(),
                ebpf::DIV32_REG | ebpf::DIV64_REG => todo!(),
                ebpf::MOD32_IMM | ebpf::MOD64_IMM => todo!(),
                ebpf::MOD32_REG | ebpf::MOD64_REG => todo!(),
                /*{
                    self.emit_muldivmod(mem, insn_ptr as u16, insn.opc, src, dst, insn.imm)
                }*/
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
                    I::LogicalShiftLeftImmediate { imm5: insn.imm as u8, rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::LSH32_REG | ebpf::LSH64_REG => {
                    I::LogicalShiftLeft { rm: src, rd: dst }.emit_into(mem)?;
                }
                ebpf::RSH32_IMM | ebpf::RSH64_IMM => {
                    I::LogicalShiftRightImmediate { imm5: insn.imm as u8, rm: src, rd: dst }.emit_into(mem)?;
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
                ebpf::JA => todo!(), //self.emit_jmp(mem, target_pc),
                ebpf::JEQ_IMM | ebpf::JEQ_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm as u16 }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::EQ, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JEQ_REG | ebpf::JEQ_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::EQ, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JGT_IMM | ebpf::JGT_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm as u16 }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::HI, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JGT_REG | ebpf::JGT_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::HI, imm: insn.off as i32 }.emit_into(mem)?;
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
                    I::CompareImmediate { rd: dst, imm: insn.imm as u16 }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::GE, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JGE_REG | ebpf::JGE_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::GE, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JLT_IMM | ebpf::JLT_IMM32 => {
                    // Note: JLT wants to use an unsigned comparison but our LT is signed -> how to
                    // get around this? Can we repurpose the Condition::HI and reordering operands?
                    I::CompareImmediate { rd: dst, imm: insn.imm  as u16 }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::LT, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JLT_REG | ebpf::JLT_REG32 => {
                    // We need to handle unsigned LT in as special way as ARM ISA
                    // doesn't provide that condition (we only have LS) which
                    // is unsigned Lower or Same.
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::LT, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JLE_IMM | ebpf::JLE_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm as u16}.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::LS, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JLE_REG | ebpf::JLE_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::LS, imm: insn.off as i32 }.emit_into(mem)?;
                }

                ebpf::JSET_IMM | ebpf::JSET_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm as u16 }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::CS, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JSET_REG | ebpf::JSET_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::CS, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JNE_IMM | ebpf::JNE_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm as u16 }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::NE, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JNE_REG | ebpf::JNE_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::NE, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JSGT_IMM | ebpf::JSGT_IMM32 =>{
                    I::CompareImmediate { rd: dst, imm: insn.imm as u16 }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::GT, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JSGT_REG | ebpf::JSGT_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::GT, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JSGE_IMM | ebpf::JSGE_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm as u16 }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::GE, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JSGE_REG | ebpf::JSGE_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::GE, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JSLT_IMM | ebpf::JSLT_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm as u16 }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::LT, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JSLT_REG | ebpf::JSLT_REG32 => {
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::LT, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JSLE_IMM | ebpf::JSLE_IMM32 => {
                    I::CompareImmediate { rd: dst, imm: insn.imm as u16}.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::LE, imm: insn.off as i32 }.emit_into(mem)?;
                }
                ebpf::JSLE_REG | ebpf::JSLE_REG32 =>{
                    I::CompareRegisters { rm: src, rd:dst }.emit_into(mem)?;
                    I::ConditionalBranch { cond: Condition::LE, imm: insn.off as i32 }.emit_into(mem)?;
                }

                ebpf::CALL => todo!(), /*{
                    // For JIT, helpers in use MUST be registered at compile time. They can be
                    // updated later, but not created after compiling (we need the address of the
                    // helper function in the JIT-compiled program).
                    if let Some(helper) = helpers.get(&(insn.imm as u32)) {
                        // We reserve R1 for shifts
                        self.emit_mov(mem, R9, R1);
                        self.emit_call(mem, *helper as usize);
                    } else {
                        Err(Error::new(
                            ErrorKind::Other,
                            format!(
                                "[JIT] Error: unknown helper function (id: {:#x})",
                                insn.imm as u32
                            ),
                        ))?;
                    };
                }*/
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
            //self.emit_mov(mem, map_register(0), R0);
        }

        // Deallocate stack space
        // The add immediate to SP instruction allows for at most 4*127 bytes
        // being shifted, so we need to do this twice to shift the stack by 512 bytes.
        let offset = ebpf::STACK_SIZE as u16 / 2;
        I::AddImmediateToSP { imm: offset }.emit_into(mem)?;
        I::AddImmediateToSP { imm: offset }.emit_into(mem)?;

        Self::restore_callee_save_registers(mem)?;

        I::BranchAndExchange { rm: LR }.emit_into(mem)?;

        Ok(())
    }

    fn resolve_jumps(&mut self, mem: &mut JitMemory) -> Result<(), Error> {
        for jump in &self.jumps {
            let target_loc = match self.special_targets.get(&jump.target_pc) {
                Some(target) => *target,
                None => self.pc_locs[jump.target_pc as usize],
            };

            // Assumes jump offset is at end of instruction
            unsafe {
                let offset_loc = jump.offset_loc as i32 + core::mem::size_of::<i32>() as i32;
                let rel = &(target_loc as i32 - offset_loc) as *const i32;

                let offset_ptr = mem.contents.as_ptr().add(jump.offset_loc);

                /* TODO: figure out how to do this without libc
                libc::memcpy(
                    offset_ptr as *mut libc::c_void,
                    rel as *const libc::c_void,
                    core::mem::size_of::<i32>(),
                );
                */
            }
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
    offset: usize,
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
    ) -> Result<JitMemory<'a>, Error> {
        let mut mem = JitMemory {
            contents: jit_memory_buff,
            offset: 0,
        };

        let mut jit = JitCompiler::new();
        jit.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
        //jit.resolve_jumps(&mut mem)?;

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
