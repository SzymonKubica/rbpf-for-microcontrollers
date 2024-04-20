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
                ebpf::LD_B_REG => todo!(), //self.emit_load(mem, OperandSize::S8, src, dst, insn.off as i32),
                ebpf::LD_H_REG => todo!(), //self.emit_load(mem, OperandSize::S16, src, dst, insn.off as i32),
                ebpf::LD_W_REG => {
                        // TODO: move this verification to the construction of the instruction
                        // encoding to automatically select the correct one based on the
                        // size of the register encoding
                        //Self::verify_register_low(src)?;
                        //Self::verify_register_low(dst)?;
                        I::LoadRegisterImmediate  { imm: insn.off, rn: src, rt: dst }.emit_into(mem)?
                }
                ebpf::LD_DW_REG => todo!(), //self.emit_load(mem, OperandSize::S64, src, dst, insn.off as i32),

                // BPF_ST class
                ebpf::ST_B_IMM => todo!(),
                /*{
                    self.emit_store_imm32(mem, OperandSize::S8, dst, insn.off as i32, insn.imm)
                }*/
                ebpf::ST_H_IMM => todo!(),
                /*{
                    self.emit_store_imm32(mem, OperandSize::S16, dst, insn.off as i32, insn.imm)
                }*/
                ebpf::ST_W_IMM => todo!(),
                /*{
                    self.emit_store_imm32(mem, OperandSize::S32, dst, insn.off as i32, insn.imm)
                }*/
                ebpf::ST_DW_IMM => todo!(),
                /*{
                    self.emit_store_imm32(mem, OperandSize::S64, dst, insn.off as i32, insn.imm)
                }*/

                // BPF_STX class
                ebpf::ST_B_REG => todo!(), //self.emit_store(mem, OperandSize::S8, src, dst, insn.off as i32),
                ebpf::ST_H_REG => todo!(), //self.emit_store(mem, OperandSize::S16, src, dst, insn.off as i32),
                ebpf::ST_W_REG => {
                    I::StoreRegisterImmediate { imm: insn.off, rn: dst, rt: src }.emit_into(mem)?
                }
                //self.emit_store(mem, OperandSize::S32, src, dst, insn.off as i32),
                ebpf::ST_DW_REG => todo!(),
                /*{
                    self.emit_store(mem, OperandSize::S64, src, dst, insn.off as i32)
                }*/
                ebpf::ST_W_XADD => unimplemented!(),
                ebpf::ST_DW_XADD => unimplemented!(),

                // BPF_ALU class
                ebpf::ADD32_IMM => todo!(), //self.emit_alu32_imm32(mem, 0x81, 0, dst, insn.imm),
                ebpf::ADD32_REG => todo!(), //self.emit_alu32(mem, 0x01, src, dst),
                ebpf::SUB32_IMM => todo!(), //self.emit_alu32_imm32(mem, 0x81, 5, dst, insn.imm),
                ebpf::SUB32_REG => todo!(), //self.emit_alu32(mem, 0x29, src, dst),
                ebpf::MUL32_IMM
                | ebpf::MUL32_REG
                | ebpf::DIV32_IMM
                | ebpf::DIV32_REG
                | ebpf::MOD32_IMM
                | ebpf::MOD32_REG => todo!(),
                /*{
                    self.emit_muldivmod(mem, insn_ptr as u16, insn.opc, src, dst, insn.imm)
                }*/
                ebpf::OR32_IMM => todo!(), //self.emit_alu32_imm32(mem, 0x81, 1, dst, insn.imm),
                ebpf::OR32_REG => todo!(), //self.emit_alu32(mem, 0x09, src, dst),
                ebpf::AND32_IMM => todo!(), //self.emit_alu32_imm32(mem, 0x81, 4, dst, insn.imm),
                ebpf::AND32_REG => todo!(), //self.emit_alu32(mem, 0x21, src, dst),
                ebpf::LSH32_IMM => todo!(), //self.emit_alu32_imm8(mem, 0xc1, 4, dst, insn.imm as i8),
                ebpf::LSH32_REG => todo!(),
                /*{
                    self.emit_mov(mem, src, R1);
                    self.emit_alu32(mem, 0xd3, 4, dst);
                }*/
                ebpf::RSH32_IMM => todo!(), //self.emit_alu32_imm8(mem, 0xc1, 5, dst, insn.imm as i8),
                ebpf::RSH32_REG => todo!(),
                /*{
                    self.emit_mov(mem, src, R1);
                    self.emit_alu32(mem, 0xd3, 5, dst);
                }*/
                ebpf::NEG32 => todo!(), //self.emit_alu32(mem, 0xf7, 3, dst),
                ebpf::XOR32_IMM => todo!(), //self.emit_alu32_imm32(mem, 0x81, 6, dst, insn.imm),
                ebpf::XOR32_REG => todo!(), //self.emit_alu32(mem, 0x31, src, dst),
                ebpf::MOV32_IMM => {
                    Self::verify_immediate_size(insn.imm, 8)?;
                    I::MoveImmediate { rd: dst, imm8: insn.imm as u8}.emit_into(mem)?;
                }
                //self.emit_alu32_imm32(mem, 0xc7, 0, dst, insn.imm),
                ebpf::MOV32_REG => todo!(), //self.emit_mov(mem, src, dst),
                ebpf::ARSH32_IMM => todo!(), //self.emit_alu32_imm8(mem, 0xc1, 7, dst, insn.imm as i8),
                ebpf::ARSH32_REG => todo!(),
                /*{
                    self.emit_mov(mem, src, R1);
                    self.emit_alu32(mem, 0xd3, 7, dst);
                }*/
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

                // BPF_ALU64 class
                ebpf::ADD64_IMM => {
                    if insn.imm >> 8 > 0 {
                        Err(Error::new(
                            ErrorKind::Other,
                            format!(
                                "[JIT] Instruction ADD64_IMM with immediate {:#x} which does not fit into 8 bits.",
                                insn.imm
                            ),
                        ))?;
                    }

                    I::Add8BitImmediate { rd: dst, imm8: insn.imm as u8 }.emit_into(mem)?;
                }
                ebpf::ADD64_REG => {
                    I::AddRegistersSpecial { rm: src, rd: dst }.emit_into(mem)?;
                }

                //self.emit_alu64(mem, 0x01, src, dst),
                ebpf::SUB64_IMM => todo!(), //self.emit_alu64_imm32(mem, 0x81, 5, dst, insn.imm),
                ebpf::SUB64_REG => todo!(), //self.emit_alu64(mem, 0x29, src, dst),
                ebpf::MUL64_IMM
                | ebpf::MUL64_REG
                | ebpf::DIV64_IMM
                | ebpf::DIV64_REG
                | ebpf::MOD64_IMM
                | ebpf::MOD64_REG => todo!(),
                /*{
                    self.emit_muldivmod(mem, insn_ptr as u16, insn.opc, src, dst, insn.imm)
                }*/
                ebpf::OR64_IMM => todo!(), //self.emit_alu64_imm32(mem, 0x81, 1, dst, insn.imm),
                ebpf::OR64_REG => todo!(), //self.emit_alu64(mem, 0x09, src, dst),
                ebpf::AND64_IMM => todo!(), //self.emit_alu64_imm32(mem, 0x81, 4, dst, insn.imm),
                ebpf::AND64_REG => todo!(), //self.emit_alu64(mem, 0x21, src, dst),
                ebpf::LSH64_IMM => todo!(), //self.emit_alu64_imm8(mem, 0xc1, 4, dst, insn.imm as i8),
                ebpf::LSH64_REG => todo!(),
                /*{
                    self.emit_mov(mem, src, R1);
                    self.emit_alu64(mem, 0xd3, 4, dst);
                }*/
                ebpf::RSH64_IMM => todo!(), //self.emit_alu64_imm8(mem, 0xc1, 5, dst, insn.imm as i8),
                ebpf::RSH64_REG => todo!(),
                /*{
                    self.emit_mov(mem, src, R1);
                    self.emit_alu64(mem, 0xd3, 5, dst);
                }*/
                ebpf::NEG64 => todo!(), //self.emit_alu64(mem, 0xf7, 3, dst),
                ebpf::XOR64_IMM => todo!(), //self.emit_alu64_imm32(mem, 0x81, 6, dst, insn.imm),
                ebpf::XOR64_REG => todo!(), //self.emit_alu64(mem, 0x31, src, dst),
                ebpf::MOV64_IMM => {
                    // If the immediate doesn't fit into 8bits, we cannot translate this
                    // instruction
                    if insn.imm >> 8 > 0 {
                    Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "[JIT] Instruction MOV32_IMM with immediate {:#x} which does not fit into 8 bits.",
                            insn.imm
                        ),
                    ))?;

                    }
                    I::MoveImmediate { rd: dst, imm8: insn.imm as u8}.emit_into(mem)?;
                }
                ebpf::MOV64_REG => todo!(), //self.emit_mov(mem, src, dst),
                ebpf::ARSH64_IMM => todo!(), //self.emit_alu64_imm8(mem, 0xc1, 7, dst, insn.imm as i8),
                ebpf::ARSH64_REG => todo!(),
                /*{
                    self.emit_mov(mem, src, R1);
                    self.emit_alu64(mem, 0xd3, 7, dst);
                }*/

                // BPF_JMP class
                ebpf::JA => todo!(), //self.emit_jmp(mem, target_pc),
                ebpf::JEQ_IMM => todo!(),
                /*{
                    self.emit_cmp_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x84, target_pc);
                }*/
                ebpf::JEQ_REG => todo!(),
                /*{
                    self.emit_cmp(mem, src, dst);
                    self.emit_jcc(mem, 0x84, target_pc);
                }*/
                ebpf::JGT_IMM => todo!(),
                /*{
                    self.emit_cmp_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x87, target_pc);
                }*/
                ebpf::JGT_REG => todo!(),
                /*{
                    self.emit_cmp(mem, src, dst);
                    self.emit_jcc(mem, 0x87, target_pc);
                }*/
                ebpf::JGE_IMM => todo!(),
                /*{
                    self.emit_cmp_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x83, target_pc);
                }*/
                ebpf::JGE_REG => todo!(),
                /*{
                    self.emit_cmp(mem, src, dst);
                    self.emit_jcc(mem, 0x83, target_pc);
                }*/
                ebpf::JLT_IMM => todo!(),
                /*{
                    self.emit_cmp_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x82, target_pc);
                }*/
                ebpf::JLT_REG => todo!(),
                /*{
                    self.emit_cmp(mem, src, dst);
                    self.emit_jcc(mem, 0x82, target_pc);
                }*/
                ebpf::JLE_IMM => todo!(),
                /*{
                    self.emit_cmp_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x86, target_pc);
                }*/
                ebpf::JLE_REG => todo!(),
                /*{
                    self.emit_cmp(mem, src, dst);
                    self.emit_jcc(mem, 0x86, target_pc);
                }*/
                ebpf::JSET_IMM => todo!(),
                /*{
                    self.emit_alu64_imm32(mem, 0xf7, 0, dst, insn.imm);
                    self.emit_jcc(mem, 0x85, target_pc);
                }*/
                ebpf::JSET_REG => todo!(),
                /*{
                    self.emit_alu64(mem, 0x85, src, dst);
                    self.emit_jcc(mem, 0x85, target_pc);
                }*/
                ebpf::JNE_IMM => todo!(),
                /*{
                    self.emit_cmp_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x85, target_pc);
                }*/
                ebpf::JNE_REG => todo!(),
                /*{
                    self.emit_cmp(mem, src, dst);
                    self.emit_jcc(mem, 0x85, target_pc);
                }*/
                ebpf::JSGT_IMM => todo!(),
                /*{
                    self.emit_cmp_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x8f, target_pc);
                }*/
                ebpf::JSGT_REG => todo!(),
                /*{
                    self.emit_cmp(mem, src, dst);
                    self.emit_jcc(mem, 0x8f, target_pc);
                }*/
                ebpf::JSGE_IMM => todo!(),
                /*{
                    self.emit_cmp_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x8d, target_pc);
                }*/
                ebpf::JSGE_REG => todo!(),
                /*{
                    self.emit_cmp(mem, src, dst);
                    self.emit_jcc(mem, 0x8d, target_pc);
                }*/
                ebpf::JSLT_IMM => todo!(),
                /*{
                    self.emit_cmp_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x8c, target_pc);
                }*/
                ebpf::JSLT_REG => todo!(),
                /*{
                    self.emit_cmp(mem, src, dst);
                    self.emit_jcc(mem, 0x8c, target_pc);
                }*/
                ebpf::JSLE_IMM => todo!(),
                /*{
                    self.emit_cmp_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x8e, target_pc);
                }*/
                ebpf::JSLE_REG => todo!(),
                /*{
                    self.emit_cmp(mem, src, dst);
                    self.emit_jcc(mem, 0x8e, target_pc);
                }*/

                // BPF_JMP32 class
                ebpf::JEQ_IMM32 => todo!(),
                /*{
                    self.emit_cmp32_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x84, target_pc);
                }*/
                ebpf::JEQ_REG32 => todo!(),
                /*{
                    self.emit_cmp32(mem, src, dst);
                    self.emit_jcc(mem, 0x84, target_pc);
                }*/
                ebpf::JGT_IMM32 => todo!(),
                /*{
                    self.emit_cmp32_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x87, target_pc);
                }*/
                ebpf::JGT_REG32 => todo!(),
                /*{
                    self.emit_cmp32(mem, src, dst);
                    self.emit_jcc(mem, 0x87, target_pc);
                }*/
                ebpf::JGE_IMM32 => todo!(),
                /*{
                    self.emit_cmp32_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x83, target_pc);
                }*/
                ebpf::JGE_REG32 => todo!(),
                /*{
                    self.emit_cmp32(mem, src, dst);
                    self.emit_jcc(mem, 0x83, target_pc);
                }*/
                ebpf::JLT_IMM32 => todo!(),
                /*{
                    self.emit_cmp32_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x82, target_pc);
                }*/
                ebpf::JLT_REG32 => todo!(),
                /*{
                    self.emit_cmp32(mem, src, dst);
                    self.emit_jcc(mem, 0x82, target_pc);
                }*/
                ebpf::JLE_IMM32 => todo!(),
                /*{
                    self.emit_cmp32_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x86, target_pc);
                }*/
                ebpf::JLE_REG32 => todo!(),
                /*{
                    self.emit_cmp32(mem, src, dst);
                    self.emit_jcc(mem, 0x86, target_pc);
                }*/
                ebpf::JSET_IMM32 => todo!(),
                /*{
                    self.emit_alu32_imm32(mem, 0xf7, 0, dst, insn.imm);
                    self.emit_jcc(mem, 0x85, target_pc);
                }*/
                ebpf::JSET_REG32 => todo!(),
                /*{
                    self.emit_alu32(mem, 0x85, src, dst);
                    self.emit_jcc(mem, 0x85, target_pc);
                }*/
                ebpf::JNE_IMM32 => todo!(),
                /*{
                    self.emit_cmp32_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x85, target_pc);
                }*/
                ebpf::JNE_REG32 => todo!(),
                /*{
                    self.emit_cmp32(mem, src, dst);
                    self.emit_jcc(mem, 0x85, target_pc);
                }*/
                ebpf::JSGT_IMM32 => todo!(),
                /*{
                    self.emit_cmp32_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x8f, target_pc);
                }*/
                ebpf::JSGT_REG32 => todo!(),
                /*{
                    self.emit_cmp32(mem, src, dst);
                    self.emit_jcc(mem, 0x8f, target_pc);
                }*/
                ebpf::JSGE_IMM32 => todo!(),
                /*{
                    self.emit_cmp32_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x8d, target_pc);
                }*/
                ebpf::JSGE_REG32 => todo!(),
                /*{
                    self.emit_cmp32(mem, src, dst);
                    self.emit_jcc(mem, 0x8d, target_pc);
                }*/
                ebpf::JSLT_IMM32 => todo!(),
                /*{
                    self.emit_cmp32_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x8c, target_pc);
                }*/
                ebpf::JSLT_REG32 => todo!(),
                /*{
                    self.emit_cmp32(mem, src, dst);
                    self.emit_jcc(mem, 0x8c, target_pc);
                }*/
                ebpf::JSLE_IMM32 => todo!(),
                /*{
                    self.emit_cmp32_imm32(mem, dst, insn.imm);
                    self.emit_jcc(mem, 0x8e, target_pc);
                }*/
                ebpf::JSLE_REG32 => todo!(),
                /*{
                    self.emit_cmp32(mem, src, dst);
                    self.emit_jcc(mem, 0x8e, target_pc);
                }*/

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

        //I::MoveImmediate { rd: R0, imm8: 123 }.emit_into(mem);

        // Here we test if we can return back the third argument
        //I::MoveRegistersSpecial { rm: R10, rd: R0 }.emit_into(mem);

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
        I::StoreRegisterImmediate {
            imm,
            rn: SP,
            rt: R4,
        }
        .emit_into(mem)?;
        imm += 4;
        I::StoreRegisterImmediate {
            imm,
            rn: SP,
            rt: R5,
        }
        .emit_into(mem)?;
        imm += 4;
        I::StoreRegisterImmediate {
            imm,
            rn: SP,
            rt: R6,
        }
        .emit_into(mem)
    }

    fn restore_callee_save_registers(mem: &mut JitMemory) -> Result<(), Error> {
        let mut imm = 0;
        I::LoadRegisterImmediate {
            imm,
            rn: SP,
            rt: R4,
        }
        .emit_into(mem)?;
        imm += 4;
        I::LoadRegisterImmediate {
            imm,
            rn: SP,
            rt: R5,
        }
        .emit_into(mem)?;
        imm += 4;
        I::LoadRegisterImmediate {
            imm,
            rn: SP,
            rt: R6,
        }
        .emit_into(mem)?;
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
