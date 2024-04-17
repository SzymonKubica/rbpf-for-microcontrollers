// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for helpers)

use stdlib::collections::{BTreeMap, Vec};
use stdlib::{Error, ErrorKind, String, ToString};

use ebpf;

use crate::interpreter_common::check_mem;

#[allow(unknown_lints)]
#[allow(cyclomatic_complexity)]
pub fn execute_program(
    prog_: Option<&[u8]>,
    mem: &[u8],
    mbuff: &[u8],
    helpers: &BTreeMap<u32, ebpf::Helper>,
    allowed_memory_regions: Vec<(u64, u64)>,
) -> Result<u64, Error> {
    const U32MAX: u64 = u32::MAX as u64;
    const SHIFT_MASK_32: u32 = 0x1f;
    const SHIFT_MASK_64: u64 = 0x3f;

    let prog = match prog_ {
        Some(prog) => prog,
        None => Err(Error::new(
            ErrorKind::Other,
            "Error: No program set, call prog_set() to load one",
        ))?,
    };
    let stack = vec![0u8; ebpf::STACK_SIZE];

    // R1 points to beginning of memory area, R10 to stack
    let mut reg: [u64; 11] = [
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        stack.as_ptr() as u64 + stack.len() as u64,
    ];
    if !mbuff.is_empty() {
        reg[1] = mbuff.as_ptr() as u64;
    } else if !mem.is_empty() {
        reg[1] = mem.as_ptr() as u64;
    }

    let Ok(binary) = goblin::elf::Elf::parse(&prog) else {
        Err(Error::new(ErrorKind::Other, "Failed to parse ELF binary"))?
    };

    let Ok(text_section) = extract_section(".text", &binary, prog) else {
        Err(Error::new(ErrorKind::Other, ".text section not found"))?
    };

    let data_section = extract_section(".data", &binary, prog).map_or(None, |v| Some(v));
    let rodata_section = extract_section(".rodata", &binary, prog).map_or(None, |v| Some(v));

    let check_mem_load = |addr: u64, len: usize, insn_ptr: usize| {
        check_mem(
            addr,
            len,
            true,
            insn_ptr,
            mbuff,
            mem,
            &stack,
            data_section,
            rodata_section,
            &allowed_memory_regions,
        )
    };
    let check_mem_store = |addr: u64, len: usize, insn_ptr: usize| {
        check_mem(
            addr,
            len,
            false,
            insn_ptr,
            mbuff,
            mem,
            &stack,
            data_section,
            rodata_section,
            &allowed_memory_regions,
        )
    };

    let mut return_address_stack = vec![];

    // Loop on instructions
    let mut insn_ptr: usize = 0;
    while insn_ptr * ebpf::INSN_SIZE < prog.len() {
        let insn = ebpf::get_insn(text_section, insn_ptr);
        insn_ptr += 1;
        let _dst = insn.dst as usize;
        let _src = insn.src as usize;

        let mut do_jump = || {
            insn_ptr = (insn_ptr as i16 + insn.off) as usize;
        };

        match insn.opc {
            // BPF_LD class
            // LD_ABS_* and LD_IND_* are supposed to load pointer to data from metadata buffer.
            // Since this pointer is constant, and since we already know it (mem), do not
            // bother re-fetching it, just use mem already.
            ebpf::LD_ABS_B => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + (insn.imm as u32) as u64) as *const u8;
                    check_mem_load(x as u64, 8, insn_ptr)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_ABS_H => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + (insn.imm as u32) as u64) as *const u16;
                    check_mem_load(x as u64, 8, insn_ptr)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_ABS_W => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + (insn.imm as u32) as u64) as *const u32;
                    check_mem_load(x as u64, 8, insn_ptr)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_ABS_DW => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + (insn.imm as u32) as u64) as *const u64;
                    check_mem_load(x as u64, 8, insn_ptr)?;
                    x.read_unaligned()
                }
            }
            ebpf::LD_IND_B => {
                reg[0] = unsafe {
                    let x =
                        (mem.as_ptr() as u64 + reg[_src] + (insn.imm as u32) as u64) as *const u8;
                    check_mem_load(x as u64, 8, insn_ptr)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_IND_H => {
                reg[0] = unsafe {
                    let x =
                        (mem.as_ptr() as u64 + reg[_src] + (insn.imm as u32) as u64) as *const u16;
                    check_mem_load(x as u64, 8, insn_ptr)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_IND_W => {
                reg[0] = unsafe {
                    let x =
                        (mem.as_ptr() as u64 + reg[_src] + (insn.imm as u32) as u64) as *const u32;
                    check_mem_load(x as u64, 8, insn_ptr)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_IND_DW => {
                reg[0] = unsafe {
                    let x =
                        (mem.as_ptr() as u64 + reg[_src] + (insn.imm as u32) as u64) as *const u64;
                    check_mem_load(x as u64, 8, insn_ptr)?;
                    x.read_unaligned()
                }
            }

            ebpf::LD_DW_IMM => {
                let next_insn = ebpf::get_insn(text_section, insn_ptr);
                insn_ptr += 1;
                reg[_dst] = ((insn.imm as u32) as u64) + ((next_insn.imm as u64) << 32);
            }

            // BPF_LDX class
            ebpf::LD_B_REG => {
                reg[_dst] = unsafe {
                    #[allow(clippy::cast_ptr_alignment)]
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u8;
                    check_mem_load(x as u64, 1, insn_ptr)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_H_REG => {
                reg[_dst] = unsafe {
                    #[allow(clippy::cast_ptr_alignment)]
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u16;
                    check_mem_load(x as u64, 2, insn_ptr)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_W_REG => {
                reg[_dst] = unsafe {
                    #[allow(clippy::cast_ptr_alignment)]
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u32;
                    check_mem_load(x as u64, 4, insn_ptr)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_DW_REG => {
                reg[_dst] = unsafe {
                    #[allow(clippy::cast_ptr_alignment)]
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u64;
                    check_mem_load(x as u64, 8, insn_ptr)?;
                    x.read_unaligned()
                }
            }

            // BPF_ST class
            ebpf::ST_B_IMM => unsafe {
                let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u8;
                check_mem_store(x as u64, 1, insn_ptr)?;
                x.write_unaligned(insn.imm as u8);
            },
            ebpf::ST_H_IMM => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u16;
                check_mem_store(x as u64, 2, insn_ptr)?;
                x.write_unaligned(insn.imm as u16);
            },
            ebpf::ST_W_IMM => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u32;
                check_mem_store(x as u64, 4, insn_ptr)?;
                x.write_unaligned(insn.imm as u32);
            },
            ebpf::ST_DW_IMM => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u64;
                check_mem_store(x as u64, 8, insn_ptr)?;
                x.write_unaligned(insn.imm as u64);
            },

            // BPF_STX class
            ebpf::ST_B_REG => unsafe {
                let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u8;
                check_mem_store(x as u64, 1, insn_ptr)?;
                x.write_unaligned(reg[_src] as u8);
            },
            ebpf::ST_H_REG => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u16;
                check_mem_store(x as u64, 2, insn_ptr)?;
                x.write_unaligned(reg[_src] as u16);
            },
            ebpf::ST_W_REG => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u32;
                check_mem_store(x as u64, 4, insn_ptr)?;
                x.write_unaligned(reg[_src] as u32);
            },
            ebpf::ST_DW_REG => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u64;
                check_mem_store(x as u64, 8, insn_ptr)?;
                x.write_unaligned(reg[_src]);
            },
            ebpf::ST_W_XADD => unimplemented!(),
            ebpf::ST_DW_XADD => unimplemented!(),

            // BPF_ALU class
            // TODO Check how overflow works in kernel. Should we &= U32MAX all src register value
            // before we do the operation?
            // Cf ((0x11 << 32) - (0x1 << 32)) as u32 VS ((0x11 << 32) as u32 - (0x1 << 32) as u32
            ebpf::ADD32_IMM => reg[_dst] = (reg[_dst] as i32).wrapping_add(insn.imm) as u64, //((reg[_dst] & U32MAX) + insn.imm  as u64)     & U32MAX,
            ebpf::ADD32_REG => reg[_dst] = (reg[_dst] as i32).wrapping_add(reg[_src] as i32) as u64, //((reg[_dst] & U32MAX) + (reg[_src] & U32MAX)) & U32MAX,
            ebpf::SUB32_IMM => reg[_dst] = (reg[_dst] as i32).wrapping_sub(insn.imm) as u64,
            ebpf::SUB32_REG => reg[_dst] = (reg[_dst] as i32).wrapping_sub(reg[_src] as i32) as u64,
            ebpf::MUL32_IMM => reg[_dst] = (reg[_dst] as i32).wrapping_mul(insn.imm) as u64,
            ebpf::MUL32_REG => reg[_dst] = (reg[_dst] as i32).wrapping_mul(reg[_src] as i32) as u64,
            ebpf::DIV32_IMM if insn.imm as u32 == 0 => reg[_dst] = 0,
            ebpf::DIV32_IMM => reg[_dst] = (reg[_dst] as u32 / insn.imm as u32) as u64,
            ebpf::DIV32_REG if reg[_src] as u32 == 0 => reg[_dst] = 0,
            ebpf::DIV32_REG => reg[_dst] = (reg[_dst] as u32 / reg[_src] as u32) as u64,
            ebpf::OR32_IMM => reg[_dst] = (reg[_dst] as u32 | insn.imm as u32) as u64,
            ebpf::OR32_REG => reg[_dst] = (reg[_dst] as u32 | reg[_src] as u32) as u64,
            ebpf::AND32_IMM => reg[_dst] = (reg[_dst] as u32 & insn.imm as u32) as u64,
            ebpf::AND32_REG => reg[_dst] = (reg[_dst] as u32 & reg[_src] as u32) as u64,
            ebpf::LSH32_IMM => {
                reg[_dst] = (reg[_dst] as u32).wrapping_shl(insn.imm as u32 & SHIFT_MASK_32) as u64
            }
            ebpf::LSH32_REG => {
                reg[_dst] = (reg[_dst] as u32).wrapping_shl(reg[_src] as u32 & SHIFT_MASK_32) as u64
            }
            ebpf::RSH32_IMM => {
                reg[_dst] = (reg[_dst] as u32).wrapping_shr(insn.imm as u32 & SHIFT_MASK_32) as u64
            }
            ebpf::RSH32_REG => {
                reg[_dst] = (reg[_dst] as u32).wrapping_shr(reg[_src] as u32 & SHIFT_MASK_32) as u64
            }
            ebpf::NEG32 => {
                reg[_dst] = (reg[_dst] as i32).wrapping_neg() as u64;
                reg[_dst] &= U32MAX;
            }
            ebpf::MOD32_IMM if insn.imm as u32 == 0 => (),
            ebpf::MOD32_IMM => reg[_dst] = (reg[_dst] as u32 % insn.imm as u32) as u64,
            ebpf::MOD32_REG if reg[_src] as u32 == 0 => (),
            ebpf::MOD32_REG => reg[_dst] = (reg[_dst] as u32 % reg[_src] as u32) as u64,
            ebpf::XOR32_IMM => reg[_dst] = (reg[_dst] as u32 ^ insn.imm as u32) as u64,
            ebpf::XOR32_REG => reg[_dst] = (reg[_dst] as u32 ^ reg[_src] as u32) as u64,
            ebpf::MOV32_IMM => reg[_dst] = insn.imm as u32 as u64,
            ebpf::MOV32_REG => reg[_dst] = (reg[_src] as u32) as u64,
            ebpf::ARSH32_IMM => {
                reg[_dst] = (reg[_dst] as i32).wrapping_shr(insn.imm as u32) as u64;
                reg[_dst] &= U32MAX;
            }
            ebpf::ARSH32_REG => {
                reg[_dst] = (reg[_dst] as i32).wrapping_shr(reg[_src] as u32) as u64;
                reg[_dst] &= U32MAX;
            }
            ebpf::LE => {
                reg[_dst] = match insn.imm {
                    16 => (reg[_dst] as u16).to_le() as u64,
                    32 => (reg[_dst] as u32).to_le() as u64,
                    64 => reg[_dst].to_le(),
                    _ => unreachable!(),
                };
            }
            ebpf::BE => {
                reg[_dst] = match insn.imm {
                    16 => (reg[_dst] as u16).to_be() as u64,
                    32 => (reg[_dst] as u32).to_be() as u64,
                    64 => reg[_dst].to_be(),
                    _ => unreachable!(),
                };
            }

            // BPF_ALU64 class
            ebpf::ADD64_IMM => reg[_dst] = reg[_dst].wrapping_add(insn.imm as u64),
            ebpf::ADD64_REG => reg[_dst] = reg[_dst].wrapping_add(reg[_src]),
            ebpf::SUB64_IMM => reg[_dst] = reg[_dst].wrapping_sub(insn.imm as u64),
            ebpf::SUB64_REG => reg[_dst] = reg[_dst].wrapping_sub(reg[_src]),
            ebpf::MUL64_IMM => reg[_dst] = reg[_dst].wrapping_mul(insn.imm as u64),
            ebpf::MUL64_REG => reg[_dst] = reg[_dst].wrapping_mul(reg[_src]),
            ebpf::DIV64_IMM if insn.imm == 0 => reg[_dst] = 0,
            ebpf::DIV64_IMM => reg[_dst] /= insn.imm as u64,
            ebpf::DIV64_REG if reg[_src] == 0 => reg[_dst] = 0,
            ebpf::DIV64_REG => reg[_dst] /= reg[_src],
            ebpf::OR64_IMM => reg[_dst] |= insn.imm as u64,
            ebpf::OR64_REG => reg[_dst] |= reg[_src],
            ebpf::AND64_IMM => reg[_dst] &= insn.imm as u64,
            ebpf::AND64_REG => reg[_dst] &= reg[_src],
            ebpf::LSH64_IMM => reg[_dst] <<= insn.imm as u64 & SHIFT_MASK_64,
            ebpf::LSH64_REG => reg[_dst] <<= reg[_src] & SHIFT_MASK_64,
            ebpf::RSH64_IMM => reg[_dst] >>= insn.imm as u64 & SHIFT_MASK_64,
            ebpf::RSH64_REG => reg[_dst] >>= reg[_src] & SHIFT_MASK_64,
            ebpf::NEG64 => reg[_dst] = -(reg[_dst] as i64) as u64,
            ebpf::MOD64_IMM if insn.imm == 0 => (),
            ebpf::MOD64_IMM => reg[_dst] %= insn.imm as u64,
            ebpf::MOD64_REG if reg[_src] == 0 => (),
            ebpf::MOD64_REG => reg[_dst] %= reg[_src],
            ebpf::XOR64_IMM => reg[_dst] ^= insn.imm as u64,
            ebpf::XOR64_REG => reg[_dst] ^= reg[_src],
            ebpf::MOV64_IMM => reg[_dst] = insn.imm as u64,
            ebpf::MOV64_REG => reg[_dst] = reg[_src],
            ebpf::ARSH64_IMM => reg[_dst] = (reg[_dst] as i64 >> insn.imm) as u64,
            ebpf::ARSH64_REG => reg[_dst] = (reg[_dst] as i64 >> reg[_src]) as u64,

            // BPF_JMP class
            // TODO: check this actually works as expected for signed / unsigned ops
            ebpf::JA => do_jump(),
            ebpf::JEQ_IMM => {
                if reg[_dst] == insn.imm as u64 {
                    do_jump();
                }
            }
            ebpf::JEQ_REG => {
                if reg[_dst] == reg[_src] {
                    do_jump();
                }
            }
            ebpf::JGT_IMM => {
                if reg[_dst] > insn.imm as u64 {
                    do_jump();
                }
            }
            ebpf::JGT_REG => {
                if reg[_dst] > reg[_src] {
                    do_jump();
                }
            }
            ebpf::JGE_IMM => {
                if reg[_dst] >= insn.imm as u64 {
                    do_jump();
                }
            }
            ebpf::JGE_REG => {
                if reg[_dst] >= reg[_src] {
                    do_jump();
                }
            }
            ebpf::JLT_IMM => {
                if reg[_dst] < insn.imm as u64 {
                    do_jump();
                }
            }
            ebpf::JLT_REG => {
                if reg[_dst] < reg[_src] {
                    do_jump();
                }
            }
            ebpf::JLE_IMM => {
                if reg[_dst] <= insn.imm as u64 {
                    do_jump();
                }
            }
            ebpf::JLE_REG => {
                if reg[_dst] <= reg[_src] {
                    do_jump();
                }
            }
            ebpf::JSET_IMM => {
                if reg[_dst] & insn.imm as u64 != 0 {
                    do_jump();
                }
            }
            ebpf::JSET_REG => {
                if reg[_dst] & reg[_src] != 0 {
                    do_jump();
                }
            }
            ebpf::JNE_IMM => {
                if reg[_dst] != insn.imm as u64 {
                    do_jump();
                }
            }
            ebpf::JNE_REG => {
                if reg[_dst] != reg[_src] {
                    do_jump();
                }
            }
            ebpf::JSGT_IMM => {
                if reg[_dst] as i64 > insn.imm as i64 {
                    do_jump();
                }
            }
            ebpf::JSGT_REG => {
                if reg[_dst] as i64 > reg[_src] as i64 {
                    do_jump();
                }
            }
            ebpf::JSGE_IMM => {
                if reg[_dst] as i64 >= insn.imm as i64 {
                    do_jump();
                }
            }
            ebpf::JSGE_REG => {
                if reg[_dst] as i64 >= reg[_src] as i64 {
                    do_jump();
                }
            }
            ebpf::JSLT_IMM => {
                if (reg[_dst] as i64) < insn.imm as i64 {
                    do_jump();
                }
            }
            ebpf::JSLT_REG => {
                if (reg[_dst] as i64) < reg[_src] as i64 {
                    do_jump();
                }
            }
            ebpf::JSLE_IMM => {
                if reg[_dst] as i64 <= insn.imm as i64 {
                    do_jump();
                }
            }
            ebpf::JSLE_REG => {
                if reg[_dst] as i64 <= reg[_src] as i64 {
                    do_jump();
                }
            }

            // BPF_JMP32 class
            ebpf::JEQ_IMM32 => {
                if reg[_dst] as u32 == insn.imm as u32 {
                    do_jump();
                }
            }
            ebpf::JEQ_REG32 => {
                if reg[_dst] as u32 == reg[_src] as u32 {
                    do_jump();
                }
            }
            ebpf::JGT_IMM32 => {
                if reg[_dst] as u32 > insn.imm as u32 {
                    do_jump();
                }
            }
            ebpf::JGT_REG32 => {
                if reg[_dst] as u32 > reg[_src] as u32 {
                    do_jump();
                }
            }
            ebpf::JGE_IMM32 => {
                if reg[_dst] as u32 >= insn.imm as u32 {
                    do_jump();
                }
            }
            ebpf::JGE_REG32 => {
                if reg[_dst] as u32 >= reg[_src] as u32 {
                    do_jump();
                }
            }
            ebpf::JLT_IMM32 => {
                if (reg[_dst] as u32) < insn.imm as u32 {
                    do_jump();
                }
            }
            ebpf::JLT_REG32 => {
                if (reg[_dst] as u32) < reg[_src] as u32 {
                    do_jump();
                }
            }
            ebpf::JLE_IMM32 => {
                if reg[_dst] as u32 <= insn.imm as u32 {
                    do_jump();
                }
            }
            ebpf::JLE_REG32 => {
                if reg[_dst] as u32 <= reg[_src] as u32 {
                    do_jump();
                }
            }
            ebpf::JSET_IMM32 => {
                if reg[_dst] as u32 & insn.imm as u32 != 0 {
                    do_jump();
                }
            }
            ebpf::JSET_REG32 => {
                if reg[_dst] as u32 & reg[_src] as u32 != 0 {
                    do_jump();
                }
            }
            ebpf::JNE_IMM32 => {
                if reg[_dst] as u32 != insn.imm as u32 {
                    do_jump();
                }
            }
            ebpf::JNE_REG32 => {
                if reg[_dst] as u32 != reg[_src] as u32 {
                    do_jump();
                }
            }
            ebpf::JSGT_IMM32 => {
                if reg[_dst] as i32 > insn.imm {
                    do_jump();
                }
            }
            ebpf::JSGT_REG32 => {
                if reg[_dst] as i32 > reg[_src] as i32 {
                    do_jump();
                }
            }
            ebpf::JSGE_IMM32 => {
                if reg[_dst] as i32 >= insn.imm {
                    do_jump();
                }
            }
            ebpf::JSGE_REG32 => {
                if reg[_dst] as i32 >= reg[_src] as i32 {
                    do_jump();
                }
            }
            ebpf::JSLT_IMM32 => {
                if (reg[_dst] as i32) < insn.imm {
                    do_jump();
                }
            }
            ebpf::JSLT_REG32 => {
                if (reg[_dst] as i32) < reg[_src] as i32 {
                    do_jump();
                }
            }
            ebpf::JSLE_IMM32 => {
                if reg[_dst] as i32 <= insn.imm {
                    do_jump();
                }
            }
            ebpf::JSLE_REG32 => {
                if reg[_dst] as i32 <= reg[_src] as i32 {
                    do_jump();
                }
            }

            // Do not delegate the check to the verifier, since registered functions can be
            // changed after the program has been verified.
            ebpf::CALL => {
                // The source register determines if we have a helper call or a PC-relative call.
                match insn.src {
                    0 => {
                        if let Some(function) = helpers.get(&(insn.imm as u32)) {
                            reg[0] = function(reg[1], reg[2], reg[3], reg[4], reg[5]);
                        } else {
                            Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Error: unknown helper function (id: {:#x})",
                                    insn.imm as u32
                                ),
                            ))?;
                        }
                    }
                    1 => {
                        // Here the source register 1 indicates that we are making
                        // a call relative to the current instruction pointer
                        return_address_stack.push(insn_ptr as u64);
                        insn_ptr = ((insn_ptr as i32 + insn.imm) as usize) as usize;
                    }
                    3 => {
                        // This is a hacky implementation of calling functions
                        // using their actual memory address (not specified in the
                        // eBPF standard). Those calls are denoted by value 3
                        // being present in the source register. The reason we
                        // need those is when we want to have non-inlined, non-static
                        // functions defined inside of eBPF programs. Calls to those
                        // functions aren't compiled as PC-relative calls and
                        // they need manual relocation resolution

                        return_address_stack.push(insn_ptr as u64);
                        let function_address = insn.imm as u32;
                        let program_address = prog.as_ptr() as u32;
                        let function_offset = function_address - program_address as u32;
                        insn_ptr = (function_offset / 8) as usize;
                    }
                    _ => unreachable!(),
                };
            }
            ebpf::TAIL_CALL => unimplemented!(),
            ebpf::EXIT => {
                if return_address_stack.is_empty() {
                    return Ok(reg[0]);
                } else {
                    insn_ptr = return_address_stack.pop().unwrap() as usize;
                }
            }

            _ => unreachable!(),
        }
    }

    unreachable!()
}

pub fn extract_section<'a>(
    section_name: &'static str,
    binary: &'a goblin::elf::Elf<'_>,
    program: &'a [u8],
) -> Result<&'a [u8], String> {
    for section in &binary.section_headers {
        if let Some(name) = binary.shdr_strtab.get_at(section.sh_name) {
            if name == section_name {
                let section_start = section.sh_offset as usize;
                let section_end = (section.sh_offset + section.sh_size) as usize;
                return Ok(&program[section_start..section_end]);
            }
        }
    }

    return Err("Section not found".to_string());
}
