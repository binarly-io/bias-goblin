use crate::error;
use scroll::{ctx, Pread, SizeWith, Pwrite};

use crate::te::data_directories::{SIZEOF_DATA_DIRECTORIES, DataDirectories};
use crate::te::section_table;

pub const SIZEOF_TE_HEADER: usize = 24 + SIZEOF_DATA_DIRECTORIES;
pub const TE_MAGIC: u16 = 0x5a56;

pub const TE_SUBSYSTEM_UNKNOWN: u8 = 0;
pub const TE_SUBSYSTEM_NATIVE: u8 = 1;
pub const TE_SUBSYSTEM_WINDOWS_GUI: u8 = 2;
pub const TE_SUBSYSTEM_WINDOWS_CUI: u8 = 3;
pub const TE_SUBSYSTEM_POSIX_CUI: u8 = 7;
pub const TE_SUBSYSTEM_WINDOWS_CE_GUI: u8 = 9;
pub const TE_SUBSYSTEM_EFI_APPLICATION: u8 = 10;
pub const TE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u8 = 11;
pub const TE_SUBSYSTEM_EFI_RUNTIME_DRIVER: u8 = 12;
pub const TE_SUBSYSTEM_EFI_ROM: u8 = 13;
pub const TE_SUBSYSTEM_XBOX: u8 = 14;
pub const TE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: u8 = 16;

pub const TE_MACHINE_UNKNOWN: u16 = 0x0;
/// Matsushita AM33
pub const TE_MACHINE_AM33: u16 = 0x1d3;
/// x64
pub const TE_MACHINE_X86_64: u16 = 0x8664;
/// ARM little endian
pub const TE_MACHINE_ARM: u16 = 0x1c0;
/// ARM64 little endian
pub const TE_MACHINE_ARM64: u16 = 0xaa64;
/// ARM Thumb-2 little endian
pub const TE_MACHINE_ARMNT: u16 = 0x1c4;
/// EFI byte code
pub const TE_MACHINE_EBC: u16 = 0xebc;
/// Intel 386 or later processors and compatible processors
pub const TE_MACHINE_X86: u16 = 0x14c;
/// Intel Itanium processor family
pub const TE_MACHINE_IA64: u16 = 0x200;
/// Mitsubishi M32R little endian
pub const TE_MACHINE_M32R: u16 = 0x9041;
/// MIPS16
pub const TE_MACHINE_MIPS16: u16 = 0x266;
/// MIPS with FPU
pub const TE_MACHINE_MIPSFPU: u16 = 0x366;
/// MIPS16 with FPU
pub const TE_MACHINE_MIPSFPU16: u16 = 0x466;
/// Power PC little endian
pub const TE_MACHINE_POWERPC: u16 = 0x1f0;
/// Power PC with floating point support
pub const TE_MACHINE_POWERPCFP: u16 = 0x1f1;
/// MIPS little endian
pub const TE_MACHINE_R4000: u16 = 0x166;
/// RISC-V 32-bit address space
pub const TE_MACHINE_RISCV32: u16 = 0x5032;
/// RISC-V 64-bit address space
pub const TE_MACHINE_RISCV64: u16 = 0x5064;
/// RISC-V 128-bit address space
pub const TE_MACHINE_RISCV128: u16 = 0x5128;
/// Hitachi SH3
pub const TE_MACHINE_SH3: u16 = 0x1a2;
/// Hitachi SH3 DSP
pub const TE_MACHINE_SH3DSP: u16 = 0x1a3;
/// Hitachi SH4
pub const TE_MACHINE_SH4: u16 = 0x1a6;
/// Hitachi SH5
pub const TE_MACHINE_SH5: u16 = 0x1a8;
/// Thumb
pub const TE_MACHINE_THUMB: u16 = 0x1c2;
/// MIPS little-endian WCE v2
pub const TE_MACHINE_WCEMIPSV2: u16 = 0x169;

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Pread, SizeWith)]
pub struct Header {
    pub signature: u16,
    pub machine: u16,
    pub number_of_sections: u8,
    pub subsystem: u8,
    pub stripped_size: u16,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub data_directories: DataDirectories,
}

impl ctx::TryIntoCtx<scroll::Endian> for Header {
    type Error = error::Error;

    fn try_into_ctx(self, bytes: &mut [u8], ctx: scroll::Endian) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        bytes.gwrite_with(self.signature, offset, ctx)?;
        bytes.gwrite_with(self.machine, offset, ctx)?;
        bytes.gwrite_with(self.number_of_sections, offset, ctx)?;
        bytes.gwrite_with(self.subsystem, offset, ctx)?;
        bytes.gwrite_with(self.stripped_size, offset, ctx)?;
        bytes.gwrite_with(self.address_of_entry_point, offset, ctx)?;
        bytes.gwrite_with(self.base_of_code, offset, ctx)?;
        bytes.gwrite_with(self.image_base, offset, ctx)?;
        bytes.gwrite_with(self.data_directories, offset, ctx)?;

        Ok(SIZEOF_TE_HEADER)
    }
}

impl ctx::IntoCtx<scroll::Endian> for Header {
    fn into_ctx(self, bytes: &mut [u8], ctx: scroll::Endian) {
        bytes.pwrite_with(self, 0, ctx).unwrap();
    }
}

impl Header {
    pub fn parse(bytes: &[u8]) -> error::Result<Self> {
        let header = bytes.pread_with::<Self>(0, scroll::LE)?;
        if header.signature != TE_MAGIC {
            return Err(error::Error::Malformed(format!(
                "TE header is malformed (signature: {:#x})",
                header.signature
            )));
        }
        Ok(header)
    }

    pub fn sections(
        &self,
        bytes: &[u8],
        offset: &mut usize,
    ) -> error::Result<Vec<section_table::SectionTable>> {
        let nsections = self.number_of_sections as usize;
        let mut sections = Vec::with_capacity(nsections);

        for i in 0..nsections {
            let section =
                section_table::SectionTable::parse(bytes, offset)?;
            log::debug!("({}) {:#?}", i, section);
            sections.push(section);
        }

        Ok(sections)
    }
}
