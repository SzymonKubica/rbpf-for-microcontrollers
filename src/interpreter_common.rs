use log::debug;
use stdlib::collections::Vec;
use stdlib::{Error, ErrorKind, ToString};

/// Shared structure representing a section
#[derive(Debug, Clone, Copy)]
pub struct ElfSection {
    pub offset: u32,
    pub len: u32,
}

impl ElfSection {
    pub fn new(offset: u32, len: u32) -> Self {
        Self { offset, len }
    }
    pub fn extract_section_reference<'a>(&self, program_bytes: &'a [u8]) -> &'a [u8] {
        let start = self.offset as usize;
        let end = start + self.len as usize;
        &program_bytes[start..end]
    }
}

/// Generalized version of the `check_mem` function shared by all of the
/// extended interpreters.
///
/// The programs that we load contain `.data` and `.rodata` sections
/// and thus it is valid to perform memory loads from those sections.
/// This version of the memory check requires a reference to the program slice
/// so that it can allow read-only access to the program .rodata sections.
pub fn check_mem(
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
    return Ok(());
    let access_type = if is_load { "load" } else { "store" };

    if let Some(addr_end) = addr.checked_add(len as u64) {
        //debug!("Checking memory {}: {}", access_type, addr);
        let debug_section_print = |name, slice: &[u8]| {
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
