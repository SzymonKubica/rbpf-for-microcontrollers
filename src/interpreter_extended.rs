// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for helpers)

//! Module provides an alternative implementation of the eBPF program interpreter.
//! The interpreter is an extension of the one used by Femto-Containers
//! <https://github.com/future-proof-iot/middleware2022-femtocontainers/tree/main>
//! Contrasted with the default implementation of the rbpf interpreter, this one
//! operates on a program binary which includes .data, .rodata and .text sections
//! as well as a header with metadata specifying the lengths of the corresponsing
//! sections. It also provides infromation about the relocated function calls and
//! so it supports programs with not-intlined, not-static functions being called
//! by the main function.
use crate::stdlib::println;
use crate::verifier::check_helpers;
use stdlib::collections::{BTreeMap, Vec};
use stdlib::{Error, ErrorKind};

use ebpf;


// Modification here: the programs that we load contain data and rodata sections
// and thus it is valid to perform memory loads from those sections.
// TODO: make that check more fine-grained so that it is possible to load from
// those sections only.
fn check_mem(
    addr: u64,
    len: usize,
    access_type: &str,
    insn_ptr: usize,
    mbuff: &[u8],
    prog: &[u8],
    mem: &[u8],
    stack: &[u8],
) -> Result<(), Error> {
    return Ok(());
    if let Some(addr_end) = addr.checked_add(len as u64) {
        // TODO: add proper debug logging.
        let debug = false;
        if debug {
            println!("Checking memory load: {}", addr);
            println!(
                "mbuff: start={} len={}",
                mbuff.as_ptr() as u64,
                mbuff.len() as u64
            );
            println!(
                "mem: start={} len={}",
                mem.as_ptr() as u64,
                mem.len() as u64
            );
            println!(
                "prog: start={} len={}",
                prog.as_ptr() as u64,
                prog.len() as u64
            );
        }
        if mbuff.as_ptr() as u64 <= addr && addr_end <= mbuff.as_ptr() as u64 + mbuff.len() as u64 {
            return Ok(());
        }
        if mem.as_ptr() as u64 <= addr && addr_end <= mem.as_ptr() as u64 + mem.len() as u64 {
            return Ok(());
        }
        if stack.as_ptr() as u64 <= addr && addr_end <= stack.as_ptr() as u64 + stack.len() as u64 {
            return Ok(());
        }

        // This allows accessing .data and .rodata
        if prog.as_ptr() as u64 <= addr && addr_end <= prog.as_ptr() as u64 + prog.len() as u64 {
            return Ok(());
        }
    }

    Err(Error::new(ErrorKind::Other, format!(
        "Error: out of bounds memory {} (insn #{:?}), addr {:#x}, size {:?}\nmbuff: {:#x}/{:#x}, mem: {:#x}/{:#x}, stack: {:#x}/{:#x}",
        access_type, insn_ptr, addr, len,
        mbuff.as_ptr() as u64, mbuff.len(),
        mem.as_ptr() as u64, mem.len(),
        stack.as_ptr() as u64, stack.len()
    )))
}

struct BytecodeHeader {
    magic: u32,   /*Magic number */
    version: u32, /*Version of the application */
    flags: u32,
    data_len: u32,   /*Length of the data section */
    rodata_len: u32, /*Length of the rodata section */
    text_len: u32,   /*Length of the text section */
    functions: u32,  /*Number of functions available */
}

#[derive(Copy, Clone, Debug)]
struct FunctionRelocation {
    instruction_offset: u32,
    function_text_offset: u32,
}

struct Program {
    text_section_offset: usize,
    data_section_offset: usize,
    rodata_section_offset: usize,
    prog_len: usize,
    relocated_calls: Vec<FunctionRelocation>,
}

fn extract_instr_ptr(prog: &[u8]) -> Program {
    let header_size = 28;
    unsafe {
        let header = prog.as_ptr() as *const BytecodeHeader;

        let text_offset = header_size + (*header).data_len + (*header).rodata_len;
        let data_offset = header_size;
        let rodata_offset = header_size + (*header).data_len;
        let function_relocations_offset = header_size
            + (*header).data_len
            + (*header).rodata_len
            + (*header).text_len
            + (*header).functions * 6; // Each function data struct is 6 bytes.

        let mut relocated_calls = Vec::new();
        let function_relocations_data = &prog[function_relocations_offset as usize..];
        println!(
            "Processing {} relocated calls...",
            function_relocations_data.len() / 8
        );
        for i in 0..(function_relocations_data.len() / 8) {
            // Each of the relocation structs is 8 bytes long
            let reloc = function_relocations_data[i * 8 as usize..(i * 8 + 8) as usize].as_ptr()
                as *const FunctionRelocation;
            println!("Relocation call found: {:?}", *reloc);
            relocated_calls.push(*reloc.clone())
        }
        return Program {
            text_section_offset: text_offset as usize,
            data_section_offset: data_offset as usize,
            rodata_section_offset: rodata_offset as usize,
            prog_len: (*header).text_len as usize,
            relocated_calls,
        };
    }
}

#[allow(unknown_lints)]
#[allow(cyclomatic_complexity)]
pub fn execute_program(
    prog_: Option<&[u8]>,
    mem: &[u8],
    mbuff: &[u8],
    helpers: &BTreeMap<u32, ebpf::Helper>,
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

    // Check if allowed helpers are correct
    check_helpers(prog, helpers)?;

    let mut return_address_stack = vec![];
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

    let check_mem_load = |addr: u64, len: usize, insn_ptr: usize| {
        check_mem(addr, len, "load", insn_ptr, mbuff, prog, mem, &stack)
    };
    let check_mem_store = |addr: u64, len: usize, insn_ptr: usize| {
        check_mem(addr, len, "store", insn_ptr, mbuff, prog, mem, &stack)
    };

    // Loop on instructions
    let mut insn_ptr: usize = 0;
    // We need to adapt it here to work with Femto-Container bytecode.
    // The starting instruction pointer isn't the start of the program. It is
    // the start of the .text section.
    let program = extract_instr_ptr(prog);
    println!("Relocated calls: {:?}", program.relocated_calls);
    let prog_text = &prog[program.text_section_offset..];
    while insn_ptr * ebpf::INSN_SIZE < prog.len() {
        let insn = ebpf::get_insn(prog_text, insn_ptr);

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
                let next_insn = ebpf::get_insn(prog_text, insn_ptr);
                insn_ptr += 1;
                reg[_dst] = ((insn.imm as u32) as u64) + ((next_insn.imm as u64) << 32);
            }

            // The custom LDDW* instructions emmitted by the Femto-Container
            // gen_rbf script. Responsible for accessing .data and .rodata
            // sections.
            // LDDWD_OPCODE = 0xB8 LDDWR_OPCODE = 0xD8
            ebpf::LDDWD_IMM => {
                let next_insn = ebpf::get_insn(prog_text, insn_ptr);
                insn_ptr += 1;
                reg[_dst] = prog.as_ptr() as u64
                    + program.data_section_offset as u64
                    + ((insn.imm as u32) as u64)
                    + ((next_insn.imm as u64) << 32);
            }

            ebpf::LDDWR_IMM => {
                let next_insn = ebpf::get_insn(prog_text, insn_ptr);
                insn_ptr += 1;
                reg[_dst] = prog.as_ptr() as u64
                    + program.rodata_section_offset as u64
                    + ((insn.imm as u32) as u64)
                    + ((next_insn.imm as u64) << 32);
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
                //println!("Call at instruction: {}", insn_ptr as i32 - 1);
                if let Some(function) = helpers.get(&(insn.imm as u32)) {
                    reg[0] = function(reg[1], reg[2], reg[3], reg[4], reg[5]);
                } else if let Some(reloc) = program
                    .relocated_calls
                    .iter()
                    .find(|r| r.instruction_offset / 8 == insn_ptr as u32 - 1)
                {
                    // If we call a helper function we push the next instruction
                    // into the return address stack and set the instruction
                    // pointer to wherever the function lives
                    return_address_stack.push(insn_ptr as u64);
                    insn_ptr = (reloc.function_text_offset / 8) as usize;
                } else if insn.src == 1 {
                    // Here the source register 1 indicates that we are making
                    // a call relative to the current instruction pointer
                    return_address_stack.push(insn_ptr as u64);
                    insn_ptr = ((insn_ptr as i32 + insn.imm) as usize) as usize;

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
