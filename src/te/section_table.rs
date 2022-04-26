use crate::error;
use crate::pe::utils::PESectionTable;
use scroll::{ctx, Pread, Pwrite};

use super::header::SIZEOF_TE_HEADER;

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Default)]
pub struct SectionTable {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
    pub stripped_size: u32,
}

impl PESectionTable for SectionTable {
    fn name(&self) -> error::Result<&str> {
        Ok(self.name.pread(0)?)
    }

    fn virtual_size(&self) -> u32 {
        self.virtual_size
    }

    fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    fn size_of_raw_data(&self) -> u32 {
        self.size_of_raw_data
    }

    fn pointer_to_raw_data(&self) -> u32 {
        self.pointer_to_raw_data
            .wrapping_sub(self.stripped_size)
            .wrapping_add(SIZEOF_TE_HEADER as u32)
    }

    fn pointer_to_relocations(&self) -> u32 {
        self.pointer_to_relocations
            .wrapping_sub(self.stripped_size)
            .wrapping_add(SIZEOF_TE_HEADER as u32)
    }

    fn pointer_to_linenumbers(&self) -> u32 {
        self.pointer_to_linenumbers
            .wrapping_sub(self.stripped_size)
            .wrapping_add(SIZEOF_TE_HEADER as u32)
    }

    fn number_of_relocations(&self) -> u16 {
        self.number_of_relocations
    }

    fn number_of_linenumbers(&self) -> u16 {
        self.number_of_linenumbers
    }

    fn characteristics(&self) -> u32 {
        self.characteristics
    }
}

pub const SIZEOF_SECTION_TABLE: usize = 8 * 5;

impl SectionTable {
    pub fn parse(bytes: &[u8], offset: &mut usize, stripped_size: u32) -> error::Result<Self> {
        let mut table = SectionTable::default();
        let mut name = [0u8; 8];

        name.copy_from_slice(bytes.gread_with(offset, 8)?);

        table.name = name;
        table.virtual_size = bytes.gread_with(offset, scroll::LE)?;
        table.virtual_address = bytes.gread_with(offset, scroll::LE)?;
        table.size_of_raw_data = bytes.gread_with(offset, scroll::LE)?;
        table.pointer_to_raw_data = bytes.gread_with(offset, scroll::LE)?;
        table.pointer_to_relocations = bytes.gread_with(offset, scroll::LE)?;
        table.pointer_to_linenumbers = bytes.gread_with(offset, scroll::LE)?;
        table.number_of_relocations = bytes.gread_with(offset, scroll::LE)?;
        table.number_of_linenumbers = bytes.gread_with(offset, scroll::LE)?;
        table.characteristics = bytes.gread_with(offset, scroll::LE)?;
        table.stripped_size = stripped_size;

        Ok(table)
    }
}

impl ctx::SizeWith<scroll::Endian> for SectionTable {
    fn size_with(_ctx: &scroll::Endian) -> usize {
        SIZEOF_SECTION_TABLE
    }
}

impl ctx::TryIntoCtx<scroll::Endian> for SectionTable {
    type Error = error::Error;
    fn try_into_ctx(self, bytes: &mut [u8], ctx: scroll::Endian) -> Result<usize, Self::Error> {
        let offset = &mut 0;
        bytes.gwrite(&self.name[..], offset)?;
        bytes.gwrite_with(self.virtual_size, offset, ctx)?;
        bytes.gwrite_with(self.virtual_address, offset, ctx)?;
        bytes.gwrite_with(self.size_of_raw_data, offset, ctx)?;
        bytes.gwrite_with(self.pointer_to_raw_data, offset, ctx)?;
        bytes.gwrite_with(self.pointer_to_relocations, offset, ctx)?;
        bytes.gwrite_with(self.pointer_to_linenumbers, offset, ctx)?;
        bytes.gwrite_with(self.number_of_relocations, offset, ctx)?;
        bytes.gwrite_with(self.number_of_linenumbers, offset, ctx)?;
        bytes.gwrite_with(self.characteristics, offset, ctx)?;
        Ok(SIZEOF_SECTION_TABLE)
    }
}

impl ctx::IntoCtx<scroll::Endian> for SectionTable {
    fn into_ctx(self, bytes: &mut [u8], ctx: scroll::Endian) {
        bytes.pwrite_with(self, 0, ctx).unwrap();
    }
}

/// The section should not be padded to the next boundary. This flag is obsolete and is replaced
/// by `IMAGE_SCN_ALIGN_1BYTES`. This is valid only for object files.
pub const IMAGE_SCN_TYPE_NO_PAD: u32 = 0x0000_0008;
/// The section contains executable code.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// The section contains initialized data.
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
///  The section contains uninitialized data.
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_LNK_OTHER: u32 = 0x0000_0100;
/// The section contains comments or other information. The .drectve section has this type.
/// This is valid for object files only.
pub const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
/// The section will not become part of the image. This is valid only for object files.
pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
/// The section contains COMDAT data. This is valid only for object files.
pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
/// The section contains data referenced through the global pointer (GP).
pub const IMAGE_SCN_GPREL: u32 = 0x0000_8000;
pub const IMAGE_SCN_MEM_PURGEABLE: u32 = 0x0002_0000;
pub const IMAGE_SCN_MEM_16BIT: u32 = 0x0002_0000;
pub const IMAGE_SCN_MEM_LOCKED: u32 = 0x0004_0000;
pub const IMAGE_SCN_MEM_PRELOAD: u32 = 0x0008_0000;

pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x0010_0000;
pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x0020_0000;
pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x0030_0000;
pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x0040_0000;
pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x0050_0000;
pub const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x0060_0000;
pub const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x0070_0000;
pub const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x0080_0000;
pub const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x0090_0000;
pub const IMAGE_SCN_ALIGN_512BYTES: u32 = 0x00A0_0000;
pub const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0x00B0_0000;
pub const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0x00C0_0000;
pub const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0x00D0_0000;
pub const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0x00E0_0000;
pub const IMAGE_SCN_ALIGN_MASK: u32 = 0x00F0_0000;

/// The section contains extended relocations.
pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
/// The section can be discarded as needed.
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
/// The section cannot be cached.
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x0400_0000;
/// The section is not pageable.
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x0800_0000;
/// The section can be shared in memory.
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
/// The section can be executed as code.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// The section can be read.
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// The section can be written to.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
