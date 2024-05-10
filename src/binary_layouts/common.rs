
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
