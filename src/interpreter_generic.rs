// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for helpers)
// Copyright 2024 Szymon Kubica <szymo.kubica@gmail.com>
//      (Add support for different binary file layouts and pc-relative calls)


use alloc::boxed::Box;
use alloc::string::ToString;
use log::debug;

use ebpf;

use crate::lib::*;
use crate::binary_layouts::Binary;
use crate::ebpf::InsnLike;

#[allow(unknown_lints)]
#[allow(cyclomatic_complexity)]
pub fn execute_program<'a>(
    prog: &'a [u8],
    mem: &[u8],
    mbuff: &[u8],
    helpers: &HashMap<u32, ebpf::Helper>,
    allowed_memory_regions: Vec<(u64, u64)>,
    binary: Box<dyn Binary + 'a>,
) -> Result<u64, Error> {
    const U32MAX: u64 = u32::MAX as u64;
    const SHIFT_MASK_32: u32 = 0x1f;
    const SHIFT_MASK_64: u64 = 0x3f;

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

    let text_section = binary.get_text_section(prog)?;
    // data and rodata sections are optional, therefore we don't error when
    // they are not found.
    let data_section = binary.get_data_section(prog).map_or(None, |v| Some(v));
    let rodata_section = binary.get_rodata_section(prog).map_or(None, |v| Some(v));

    // Stack needs to be at the beginning of the allowed memory regions to
    // make the stack lookups the fastest. (In the other cases we need to traverse
    // the list). This is because the stack is likely to be the most frequently
    // accessed memory location.
    let mut allowed_regions = vec![
        (
            stack.as_ptr() as usize,
            stack.as_ptr() as usize + stack.len() as usize,
            MemoryRegionType::Read as u8 | MemoryRegionType::Write as u8,
        ),
        (
            mem.as_ptr() as usize,
            mem.as_ptr() as usize + mem.len() as usize,
            MemoryRegionType::Read as u8 | MemoryRegionType::Write as u8,
        ),
        (
            mbuff.as_ptr() as usize,
            mbuff.as_ptr() as usize + mbuff.len() as usize,
            MemoryRegionType::Read as u8 | MemoryRegionType::Write as u8,
        ),
    ];
    debug!("Allowed memory regions: \n");
    debug!(
        "Stack: {:#x} - {:#x}",
        stack.as_ptr() as usize,
        stack.as_ptr() as usize + stack.len()
    );
    debug!(
        "Mem: {:#x} - {:#x}",
        mem.as_ptr() as usize,
        mem.as_ptr() as usize + mem.len()
    );
    debug!(
        "MBuff: {:#x} - {:#x}",
        mbuff.as_ptr() as usize,
        mbuff.as_ptr() as usize + mem.len()
    );

    for (i, region) in allowed_memory_regions.iter().enumerate() {
        // The passed-in memory regions specify the length in the second element of
        // the tuple, not the end of the region
        allowed_regions.push((
            region.0 as usize,
            (region.0 + region.1) as usize,
            MemoryRegionType::Read as u8,
        ));
        debug!(
            "Extra region #{}: {:#x} - {:#x}",
            i,
            region.0 as usize,
            (region.0 + region.1) as usize
        );
    }

    if let Some(section) = rodata_section {
        allowed_regions.push((
            section.as_ptr() as usize,
            section.as_ptr() as usize + section.len() as usize,
            MemoryRegionType::Read as u8,
        ));
        debug!(
            ".rodata: {:#x} - {:#x}",
            section.as_ptr() as usize,
            section.as_ptr() as usize + section.len()
        );
    }
    if let Some(section) = data_section {
        allowed_regions.push((
            section.as_ptr() as usize,
            section.as_ptr() as usize + section.len() as usize,
            MemoryRegionType::Read as u8 | MemoryRegionType::Write as u8,
        ));
        debug!(
            ".data: {:#x} - {:#x}",
            section.as_ptr() as usize,
            section.as_ptr() as usize + section.len()
        );
    }

    // Return address stack for pc-relative function calls. Every time we such
    // call, we push the current pc onto the stack and then pop from it when
    // we encounter an EXIT instruction.
    let mut return_address_stack = vec![];

    let caching_enabled = option_env!("CACHE_MEM_CHECKS").is_some();
    let mut read_access_cache: Vec<Option<usize>> = if caching_enabled {
        vec![None; text_section.len()]
    } else {
        vec![]
    };
    let mut write_access_cache: Vec<Option<usize>> = if caching_enabled {
        vec![None; text_section.len()]
    } else {
        vec![]
    };

    let mut check_mem_read: Box<dyn FnMut(usize, usize, usize) -> Result<(), Error>> =
        if caching_enabled {
            Box::new(|pc, addr, len| {
                check_mem_cache(
                    pc,
                    addr,
                    len,
                    MemoryRegionType::Read as u8,
                    &allowed_regions,
                    &mut read_access_cache,
                )
            })
        } else {
            Box::new(|pc, addr, len| {
                check_mem(addr, len, MemoryRegionType::Read as u8, &allowed_regions)
            })
        };

    let mut check_mem_write: Box<dyn FnMut(usize, usize, usize) -> Result<(), Error>> =
        if caching_enabled {
            Box::new(|pc, addr, len| {
                check_mem_cache(
                    pc,
                    addr,
                    len,
                    MemoryRegionType::Write as u8,
                    &allowed_regions,
                    &mut write_access_cache,
                )
            })
        } else {
            Box::new(|pc, addr, len| {
                check_mem(addr, len, MemoryRegionType::Write as u8, &allowed_regions)
            })
        };

    // Loop on instructions
    let mut insn_ptr: usize = 0;
    while insn_ptr < prog.len() {
        //let insn = ebpf::get_insn_absolute_offset(text_section, insn_ptr);
        let insn = ebpf::get_insn_fast(text_section, insn_ptr);
        insn_ptr += ebpf::INSN_SIZE;
        // we need dst register in all cases
        let _dst = insn.dst() as usize;

        match insn.opc() {
            // BPF_LD class
            // LD_ABS_* and LD_IND_* are supposed to load pointer to data from metadata buffer.
            // Since this pointer is constant, and since we already know it (mem), do not
            // bother re-fetching it, just use mem already.
            ebpf::LD_ABS_B => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as usize + (insn.imm() as u32) as usize) as *const u8;
                    check_mem_read(insn_ptr, x as usize, 8)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_ABS_H => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as usize + (insn.imm() as u32) as usize) as *const u16;
                    check_mem_read(insn_ptr, x as usize, 8)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_ABS_W => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as usize + (insn.imm() as u32) as usize) as *const u32;
                    check_mem_read(insn_ptr, x as usize, 8)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_ABS_DW => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as usize + (insn.imm() as u32) as usize) as *const u64;
                    check_mem_read(insn_ptr, x as usize, 8)?;
                    x.read_unaligned()
                }
            }
            ebpf::LD_IND_B => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as usize
                        + reg[insn.src() as usize] as usize
                        + (insn.imm() as u32) as usize) as *const u8;
                    check_mem_read(insn_ptr, x as usize, 8)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_IND_H => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as usize
                        + reg[insn.src() as usize] as usize
                        + (insn.imm() as u32) as usize) as *const u16;
                    check_mem_read(insn_ptr, x as usize, 8)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_IND_W => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as usize
                        + reg[insn.src() as usize] as usize
                        + (insn.imm() as u32) as usize) as *const u32;
                    check_mem_read(insn_ptr, x as usize, 8)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_IND_DW => {
                reg[0] = unsafe {
                    let x = (mem.as_ptr() as usize
                        + reg[insn.src() as usize] as usize
                        + (insn.imm() as u32) as usize) as *const u64;
                    check_mem_read(insn_ptr, x as usize, 8)?;
                    x.read_unaligned()
                }
            }

            ebpf::LD_DW_IMM => {
                let next_insn = ebpf::get_insn_fast(text_section, insn_ptr);
                insn_ptr += ebpf::INSN_SIZE;
                reg[_dst] = ((insn.imm() as u32) as u64) + ((next_insn.imm() as u64) << 32);
            }

            // The custom LDDW* instructions used by the Femto-Container versions
            // of the bytecode. Responsible for accessing .data and .rodata
            // sections. Will only be used in binaries that were preprocessed
            // to be compatible with the Femto-Containers layout.
            // LDDWD_ebpf::Opcode::OPCODE = 0xD8
            ebpf::LDDWD_IMM => {
                binary.handle_lddwd_instruction(
                    prog,
                    &insn,
                    &ebpf::get_insn_fast(text_section, insn_ptr),
                    _dst,
                    &mut insn_ptr,
                    &mut reg,
                )?;
            }

            ebpf::LDDWR_IMM => {
                binary.handle_lddwr_instruction(
                    prog,
                    &insn,
                    &ebpf::get_insn_fast(text_section, insn_ptr),
                    _dst,
                    &mut insn_ptr,
                    &mut reg,
                )?;
            }

            // BPF_LDX class
            ebpf::LD_B_REG => {
                reg[_dst] = unsafe {
                    #[allow(clippy::cast_ptr_alignment)]
                    let x = (reg[insn.src() as usize] as *const u8).offset(insn.off() as isize)
                        as *const u8;
                    check_mem_read(insn_ptr, x as usize, 1)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_H_REG => {
                reg[_dst] = unsafe {
                    #[allow(clippy::cast_ptr_alignment)]
                    let x = (reg[insn.src() as usize] as *const u8).offset(insn.off() as isize)
                        as *const u16;
                    check_mem_read(insn_ptr, x as usize, 2)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_W_REG => {
                reg[_dst] = unsafe {
                    #[allow(clippy::cast_ptr_alignment)]
                    let x = (reg[insn.src() as usize] as *const u8).offset(insn.off() as isize)
                        as *const u32;
                    check_mem_read(insn_ptr, x as usize, 4)?;
                    x.read_unaligned() as u64
                }
            }
            ebpf::LD_DW_REG => {
                reg[_dst] = unsafe {
                    #[allow(clippy::cast_ptr_alignment)]
                    let x = (reg[insn.src() as usize] as *const u8).offset(insn.off() as isize)
                        as *const u64;
                    check_mem_read(insn_ptr, x as usize, 8)?;
                    x.read_unaligned()
                }
            }

            // BPF_ST class
            ebpf::ST_B_IMM => unsafe {
                let x = (reg[_dst] as *const u8).offset(insn.off() as isize) as *mut u8;
                check_mem_write(insn_ptr, x as usize, 1)?;
                x.write_unaligned(insn.imm() as u8)
            },
            ebpf::ST_H_IMM => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off() as isize) as *mut u16;
                check_mem_write(insn_ptr, x as usize, 2)?;
                x.write_unaligned(insn.imm() as u16)
            },
            ebpf::ST_W_IMM => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off() as isize) as *mut u32;
                check_mem_write(insn_ptr, x as usize, 4)?;
                x.write_unaligned(insn.imm() as u32)
            },
            ebpf::ST_DW_IMM => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off() as isize) as *mut u64;
                check_mem_write(insn_ptr, x as usize, 8)?;
                x.write_unaligned(insn.imm() as u64)
            },

            // BPF_STX class
            ebpf::ST_B_REG => unsafe {
                let x = (reg[_dst] as *const u8).offset(insn.off() as isize) as *mut u8;
                check_mem_write(insn_ptr, x as usize, 1)?;
                x.write_unaligned(reg[insn.src() as usize] as u8)
            },
            ebpf::ST_H_REG => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off() as isize) as *mut u16;
                check_mem_write(insn_ptr, x as usize, 2)?;
                x.write_unaligned(reg[insn.src() as usize] as u16)
            },
            ebpf::ST_W_REG => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off() as isize) as *mut u32;
                check_mem_write(insn_ptr, x as usize, 4)?;
                x.write_unaligned(reg[insn.src() as usize] as u32)
            },
            ebpf::ST_DW_REG => unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                let x = (reg[_dst] as *const u8).offset(insn.off() as isize) as *mut u64;
                check_mem_write(insn_ptr, x as usize, 8)?;
                x.write_unaligned(reg[insn.src() as usize])
            },
            ebpf::ST_W_XADD => unimplemented!(),
            ebpf::ST_DW_XADD => unimplemented!(),

            // BPF_ALU class
            // TODO Check how overflow works in kernel. Should we &= U32MAX all src register value
            // before we do the operation?
            // Cf ((0x11 << 32) - (0x1 << 32)) as u32 VS ((0x11 << 32) as u32 - (0x1 << 32) as u32
            ebpf::ADD32_IMM => {
                reg[_dst] = (reg[_dst] as i32).wrapping_add(insn.imm()) as u64
            } //((reg[_dst] & U32MAX) + insn.imm  as u64)     & U32MAX,
            ebpf::ADD32_REG => {
                reg[_dst] = (reg[_dst] as i32).wrapping_add(reg[insn.src() as usize] as i32) as u64
            } //((reg[_dst] & U32MAX) + (reg[insn.src() as usize] & U32MAX)) & U32MAX,
            ebpf::SUB32_IMM => {
                reg[_dst] = (reg[_dst] as i32).wrapping_sub(insn.imm()) as u64
            }
            ebpf::SUB32_REG => {
                reg[_dst] = (reg[_dst] as i32).wrapping_sub(reg[insn.src() as usize] as i32) as u64
            }
            ebpf::MUL32_IMM => {
                reg[_dst] = (reg[_dst] as i32).wrapping_mul(insn.imm()) as u64
            }
            ebpf::MUL32_REG => {
                reg[_dst] = (reg[_dst] as i32).wrapping_mul(reg[insn.src() as usize] as i32) as u64
            }
            ebpf::DIV32_IMM if insn.imm() as u32 == 0 => reg[_dst] = 0,
            ebpf::DIV32_IMM => reg[_dst] = (reg[_dst] as u32 / insn.imm() as u32) as u64,
            ebpf::DIV32_REG if reg[insn.src() as usize] as u32 == 0 => reg[_dst] = 0,
            ebpf::DIV32_REG => {
                reg[_dst] = (reg[_dst] as u32 / reg[insn.src() as usize] as u32) as u64
            }
            ebpf::OR32_IMM => reg[_dst] = (reg[_dst] as u32 | insn.imm() as u32) as u64,
            ebpf::OR32_REG => {
                reg[_dst] = (reg[_dst] as u32 | reg[insn.src() as usize] as u32) as u64
            }
            ebpf::AND32_IMM => reg[_dst] = (reg[_dst] as u32 & insn.imm() as u32) as u64,
            ebpf::AND32_REG => {
                reg[_dst] = (reg[_dst] as u32 & reg[insn.src() as usize] as u32) as u64
            }
            ebpf::LSH32_IMM => {
                reg[_dst] =
                    (reg[_dst] as u32).wrapping_shl(insn.imm() as u32 & SHIFT_MASK_32) as u64
            }
            ebpf::LSH32_REG => {
                reg[_dst] = (reg[_dst] as u32)
                    .wrapping_shl(reg[insn.src() as usize] as u32 & SHIFT_MASK_32)
                    as u64
            }
            ebpf::RSH32_IMM => {
                reg[_dst] =
                    (reg[_dst] as u32).wrapping_shr(insn.imm() as u32 & SHIFT_MASK_32) as u64
            }
            ebpf::RSH32_REG => {
                reg[_dst] = (reg[_dst] as u32)
                    .wrapping_shr(reg[insn.src() as usize] as u32 & SHIFT_MASK_32)
                    as u64
            }
            ebpf::NEG32 => {
                reg[_dst] = (reg[_dst] as i32).wrapping_neg() as u64;
                reg[_dst] &= U32MAX;
            }
            ebpf::MOD32_IMM if insn.imm() as u32 == 0 => (),
            ebpf::MOD32_IMM => reg[_dst] = (reg[_dst] as u32 % insn.imm() as u32) as u64,
            ebpf::MOD32_REG if reg[insn.src() as usize] as u32 == 0 => (),
            ebpf::MOD32_REG => {
                reg[_dst] = (reg[_dst] as u32 % reg[insn.src() as usize] as u32) as u64
            }
            ebpf::XOR32_IMM => reg[_dst] = (reg[_dst] as u32 ^ insn.imm() as u32) as u64,
            ebpf::XOR32_REG => {
                reg[_dst] = (reg[_dst] as u32 ^ reg[insn.src() as usize] as u32) as u64
            }
            ebpf::MOV32_IMM => reg[_dst] = insn.imm() as u32 as u64,
            ebpf::MOV32_REG => reg[_dst] = (reg[insn.src() as usize] as u32) as u64,
            ebpf::ARSH32_IMM => {
                reg[_dst] = (reg[_dst] as i32).wrapping_shr(insn.imm() as u32) as u64;
                reg[_dst] &= U32MAX;
            }
            ebpf::ARSH32_REG => {
                reg[_dst] = (reg[_dst] as i32).wrapping_shr(reg[insn.src() as usize] as u32) as u64;
                reg[_dst] &= U32MAX;
            }
            ebpf::LE => {
                reg[_dst] = match insn.imm() {
                    16 => (reg[_dst] as u16).to_le() as u64,
                    32 => (reg[_dst] as u32).to_le() as u64,
                    64 => reg[_dst].to_le(),
                    _ => unreachable!(),
                };
            }
            ebpf::BE => {
                reg[_dst] = match insn.imm() {
                    16 => (reg[_dst] as u16).to_be() as u64,
                    32 => (reg[_dst] as u32).to_be() as u64,
                    64 => reg[_dst].to_be(),
                    _ => unreachable!(),
                };
            }

            // BPF_ALU64 class
            ebpf::ADD64_IMM => reg[_dst] = reg[_dst].wrapping_add(insn.imm() as u64),
            ebpf::ADD64_REG => {
                reg[_dst] = reg[_dst].wrapping_add(reg[insn.src() as usize])
            }
            ebpf::SUB64_IMM => reg[_dst] = reg[_dst].wrapping_sub(insn.imm() as u64),
            ebpf::SUB64_REG => {
                reg[_dst] = reg[_dst].wrapping_sub(reg[insn.src() as usize])
            }
            ebpf::MUL64_IMM => reg[_dst] = reg[_dst].wrapping_mul(insn.imm() as u64),
            ebpf::MUL64_REG => {
                reg[_dst] = reg[_dst].wrapping_mul(reg[insn.src() as usize])
            }
            ebpf::DIV64_IMM if insn.imm() == 0 => reg[_dst] = 0,
            ebpf::DIV64_IMM => reg[_dst] /= insn.imm() as u64,
            ebpf::DIV64_REG if reg[insn.src() as usize] == 0 => reg[_dst] = 0,
            ebpf::DIV64_REG => reg[_dst] /= reg[insn.src() as usize],
            ebpf::OR64_IMM => reg[_dst] |= insn.imm() as u64,
            ebpf::OR64_REG => reg[_dst] |= reg[insn.src() as usize],
            ebpf::AND64_IMM => reg[_dst] &= insn.imm() as u64,
            ebpf::AND64_REG => reg[_dst] &= reg[insn.src() as usize],
            ebpf::LSH64_IMM => reg[_dst] <<= insn.imm() as u64 & SHIFT_MASK_64,
            ebpf::LSH64_REG => reg[_dst] <<= reg[insn.src() as usize] & SHIFT_MASK_64,
            ebpf::RSH64_IMM => reg[_dst] >>= insn.imm() as u64 & SHIFT_MASK_64,
            ebpf::RSH64_REG => reg[_dst] >>= reg[insn.src() as usize] & SHIFT_MASK_64,
            ebpf::NEG64 => reg[_dst] = -(reg[_dst] as i64) as u64,
            ebpf::MOD64_IMM if insn.imm() == 0 => (),
            ebpf::MOD64_IMM => reg[_dst] %= insn.imm() as u64,
            ebpf::MOD64_REG if reg[insn.src() as usize] == 0 => (),
            ebpf::MOD64_REG => reg[_dst] %= reg[insn.src() as usize],
            ebpf::XOR64_IMM => reg[_dst] ^= insn.imm() as u64,
            ebpf::XOR64_REG => reg[_dst] ^= reg[insn.src() as usize],
            ebpf::MOV64_IMM => reg[_dst] = insn.imm() as u64,
            ebpf::MOV64_REG => reg[_dst] = reg[insn.src() as usize],
            ebpf::ARSH64_IMM => reg[_dst] = (reg[_dst] as i64 >> insn.imm()) as u64,
            ebpf::ARSH64_REG => {
                reg[_dst] = (reg[_dst] as i64 >> reg[insn.src() as usize]) as u64
            }

            // BPF_JMP class
            // TODO: check this actually works as expected for signed / unsigned ops
            ebpf::JA => {
                insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
            }
            ebpf::JEQ_IMM => {
                if reg[_dst] == insn.imm() as u64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JEQ_REG => {
                if reg[_dst] == reg[insn.src() as usize] {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JGT_IMM => {
                if reg[_dst] > insn.imm() as u64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JGT_REG => {
                if reg[_dst] > reg[insn.src() as usize] {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JGE_IMM => {
                if reg[_dst] >= insn.imm() as u64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JGE_REG => {
                if reg[_dst] >= reg[insn.src() as usize] {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JLT_IMM => {
                if reg[_dst] < insn.imm() as u64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JLT_REG => {
                if reg[_dst] < reg[insn.src() as usize] {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JLE_IMM => {
                if reg[_dst] <= insn.imm() as u64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JLE_REG => {
                if reg[_dst] <= reg[insn.src() as usize] {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSET_IMM => {
                if reg[_dst] & insn.imm() as u64 != 0 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSET_REG => {
                if reg[_dst] & reg[insn.src() as usize] != 0 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JNE_IMM => {
                if reg[_dst] != insn.imm() as u64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JNE_REG => {
                if reg[_dst] != reg[insn.src() as usize] {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSGT_IMM => {
                if reg[_dst] as i64 > insn.imm() as i64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSGT_REG => {
                if reg[_dst] as i64 > reg[insn.src() as usize] as i64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSGE_IMM => {
                if reg[_dst] as i64 >= insn.imm() as i64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSGE_REG => {
                if reg[_dst] as i64 >= reg[insn.src() as usize] as i64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSLT_IMM => {
                if (reg[_dst] as i64) < insn.imm() as i64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSLT_REG => {
                if (reg[_dst] as i64) < reg[insn.src() as usize] as i64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSLE_IMM => {
                if reg[_dst] as i64 <= insn.imm() as i64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSLE_REG => {
                if reg[_dst] as i64 <= reg[insn.src() as usize] as i64 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }

            // BPF_JMP32 class
            ebpf::JEQ_IMM32 => {
                if reg[_dst] as u32 == insn.imm() as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JEQ_REG32 => {
                if reg[_dst] as u32 == reg[insn.src() as usize] as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JGT_IMM32 => {
                if reg[_dst] as u32 > insn.imm() as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JGT_REG32 => {
                if reg[_dst] as u32 > reg[insn.src() as usize] as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JGE_IMM32 => {
                if reg[_dst] as u32 >= insn.imm() as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JGE_REG32 => {
                if reg[_dst] as u32 >= reg[insn.src() as usize] as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JLT_IMM32 => {
                if (reg[_dst] as u32) < insn.imm() as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JLT_REG32 => {
                if (reg[_dst] as u32) < reg[insn.src() as usize] as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JLE_IMM32 => {
                if reg[_dst] as u32 <= insn.imm() as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JLE_REG32 => {
                if reg[_dst] as u32 <= reg[insn.src() as usize] as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSET_IMM32 => {
                if reg[_dst] as u32 & insn.imm() as u32 != 0 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSET_REG32 => {
                if reg[_dst] as u32 & reg[insn.src() as usize] as u32 != 0 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JNE_IMM32 => {
                if reg[_dst] as u32 != insn.imm() as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JNE_REG32 => {
                if reg[_dst] as u32 != reg[insn.src() as usize] as u32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSGT_IMM32 => {
                if reg[_dst] as i32 > insn.imm() {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSGT_REG32 => {
                if reg[_dst] as i32 > reg[insn.src() as usize] as i32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSGE_IMM32 => {
                if reg[_dst] as i32 >= insn.imm() {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSGE_REG32 => {
                if reg[_dst] as i32 >= reg[insn.src() as usize] as i32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSLT_IMM32 => {
                if (reg[_dst] as i32) < insn.imm() {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSLT_REG32 => {
                if (reg[_dst] as i32) < reg[insn.src() as usize] as i32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSLE_IMM32 => {
                if reg[_dst] as i32 <= insn.imm() {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }
            ebpf::JSLE_REG32 => {
                if reg[_dst] as i32 <= reg[insn.src() as usize] as i32 {
                    insn_ptr = (insn_ptr as i16 + insn.off() * ebpf::INSN_SIZE as i16) as usize;
                }
            }

            ebpf::CALL => binary.handle_call_instruction(
                prog,
                &mut insn_ptr,
                &insn,
                &mut reg,
                helpers,
                &mut return_address_stack,
                ebpf::INSN_SIZE,
            )?,
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

pub enum MemoryRegionType {
    Read = 0b001,
    Write = 0b010,
    Execute = 0b100,
}

impl MemoryRegionType {
    fn to_str_from_u8(variant: u8) -> &'static str {
        match variant {
            0b001 => "READ",
            0b010 => "WRITE",
            0b100 => "EXECUTE",
            _ => "Invalid memory access type",
        }
    }
}

#[inline(always)]
pub fn check_mem_cache(
    pc: usize,
    addr: usize,
    len: usize,
    access_type: u8,
    allowed_memory_regions: &Vec<(usize, usize, u8)>,
    cache: &mut Vec<Option<usize>>,
) -> Result<(), Error> {
    let end = addr + len;
    if let Some(index) = cache[pc] {
        if allowed_memory_regions[index].0 <= addr
            && end <= allowed_memory_regions[index].1
            && (access_type & allowed_memory_regions[index].2) != 0
        {
            return Ok(());
        }
    }
    for (i, region) in allowed_memory_regions.iter().enumerate() {
        if region.0 <= addr && end <= region.1 && (access_type & region.2) != 0 {
            cache[pc] = Some(i);
            return Ok(());
        }
    }
    return Err(Error::new(
        ErrorKind::Other,
        format!(
            "Error: memory {} access violation at address {:#x}",
            MemoryRegionType::to_str_from_u8(access_type),
            addr as u64
        ),
    ));
}

#[inline(always)]
pub fn check_mem(
    addr: usize,
    len: usize,
    access_type: u8,
    allowed_memory_regions: &Vec<(usize, usize, u8)>,
) -> Result<(), Error> {
    let end = addr + len;
    for region in allowed_memory_regions {
        if addr <= end && region.0 <= addr && end <= region.1 && (access_type & region.2) != 0 {
            return Ok(());
        }
    }
    Err(Error::new(
        ErrorKind::Other,
        format!(
            "Error: memory access violation at address {:#x}",
            addr as u64
        ),
    ))
}

/// Generalized version of the `check_mem` function shared by all of the
/// extended interpreters.
///
/// The programs that we load contain `.data` and `.rodata` sections
/// and thus it is valid to perform memory loads from those sections.
/// This version of the memory check requires a reference to the program slice
/// so that it can allow read-only access to the program .rodata sections.
#[inline(always)]
pub fn check_mem_old(
    addr: u64,
    len: usize,
    is_load: bool,
    insn_ptr: usize,
    mbuff: &[u8],
    mem: &[u8],
    stack: &[u8],
    data: Option<&[u8]>,
    rodata: Option<&[u8]>,
    allowed_memory_regions: &Vec<(u64, u64)>,
) -> Result<(), Error> {
    let access_type = if is_load { "load" } else { "store" };

    if let Some(addr_end) = addr.checked_add(len as u64) {
        //debug!("Checking memory {}: {}", access_type, addr);
        let debug_section_print = |_name, _slice: &[u8]| {
            //debug!(
            //    "{}: start={:#x}, len={:#x}",
            //    name,
            //    slice.as_ptr() as u64,
            //    slice.len() as u64
            //)
        };

        let within_bounds = |region: &[u8], addr, addr_end| {
            region.as_ptr() as u64 <= addr
                && addr_end <= region.as_ptr() as u64 + region.len() as u64
        };

        debug_section_print("mbuff", mbuff);
        if within_bounds(mbuff, addr, addr_end) {
            return Ok(());
        }

        debug_section_print("mem", mem);
        if within_bounds(mem, addr, addr_end) {
            return Ok(());
        }

        debug_section_print("stack", stack);
        if within_bounds(stack, addr, addr_end) {
            return Ok(());
        }

        if let Some(data) = data {
            debug_section_print(".data", data);
            if within_bounds(data, addr, addr_end) {
                return Ok(());
            }
        }

        if let Some(rodata) = rodata {
            debug_section_print(".rodata", rodata);
            // We can only load from rodata
            if is_load && within_bounds(rodata, addr, addr_end) {
                return Ok(());
            }
        }

        // We check extra memory regions at the end.
        for (start, len) in allowed_memory_regions {
            let end = start + len;
            debug!(
                "Checking allowed memory region start={:#x}, end={:#x}",
                start, end
            );
            if *start <= addr && addr_end <= end {
                return Ok(());
            }
        }
    }

    let data_str = if let Some(data) = data {
        format!(".data: {:#x}/{:#x}", data.as_ptr() as u64, data.len())
    } else {
        "".to_string()
    };

    let rodata_str = if let Some(rodata) = rodata {
        format!(".rodata: {:#x}/{:#x}", rodata.as_ptr() as u64, rodata.len())
    } else {
        "".to_string()
    };

    Err(Error::new(
        ErrorKind::Other,
        format!(
            "Out of bounds memory {} (insn #{:?}), addr {:#x}, size {:?}\n
             mbuff: {:#x}/{:#x}, mem: {:#x}/{:#x}, stack: {:#x}/{:#x}\n {} {}",
            access_type,
            insn_ptr,
            addr,
            len,
            mbuff.as_ptr() as u64,
            mbuff.len(),
            mem.as_ptr() as u64,
            mem.len(),
            stack.as_ptr() as u64,
            stack.len(),
            data_str,
            rodata_str,
        ),
    ))
}
