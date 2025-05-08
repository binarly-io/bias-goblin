use crate::error;
use alloc::string::ToString;
use scroll::Pread;

use super::options;

use crate::pe::data_directories::DataDirectory;
use crate::pe::relocation;
use core::cmp;

use log::debug;

pub trait PESectionTable: core::fmt::Debug {
    fn name(&self) -> error::Result<&str>;
    fn virtual_size(&self) -> u32;
    fn virtual_address(&self) -> u32;
    fn size_of_raw_data(&self) -> u32;
    fn pointer_to_raw_data(&self) -> u32;
    fn pointer_to_relocations(&self) -> u32;
    fn pointer_to_linenumbers(&self) -> u32;
    fn number_of_relocations(&self) -> u16;
    fn number_of_linenumbers(&self) -> u16;
    fn characteristics(&self) -> u32;

    fn relocations<'a>(&self, bytes: &'a [u8]) -> error::Result<relocation::Relocations<'a>> {
        let offset = self.pointer_to_relocations() as usize;
        let number = self.number_of_relocations() as usize;
        relocation::Relocations::parse(bytes, offset, number)
    }
}

pub fn is_in_range(rva: usize, r1: usize, r2: usize) -> bool {
    r1 <= rva && rva < r2
}

// reference: Peter Ferrie. Reliable algorithm to extract overlay of a PE. https://bit.ly/2vBX2bR
#[inline]
fn aligned_pointer_to_raw_data(pointer_to_raw_data: usize) -> usize {
    const PHYSICAL_ALIGN: usize = 0x1ff;
    pointer_to_raw_data & !PHYSICAL_ALIGN
}

#[inline]
fn section_read_size<T: PESectionTable>(section: &T, file_alignment: u32) -> usize {
    fn round_size(size: usize) -> usize {
        const PAGE_MASK: usize = 0xfff;
        (size + PAGE_MASK) & !PAGE_MASK
    }

    // Paraphrased from https://reverseengineering.stackexchange.com/a/4326 (by Peter Ferrie).
    //
    // Handles the corner cases such as mis-aligned pointers (round down) and sizes (round up)
    // Further rounding corner cases:
    // - the physical pointer should be rounded down to a multiple of 512, regardless of the value in the header
    // - the read size is rounded up by using a combination of the file alignment and 4kb
    // - the virtual size is always rounded up to a multiple of 4kb, regardless of the value in the header.
    //
    // Reference C implementation:
    //
    // long pointerToRaw = section.get(POINTER_TO_RAW_DATA);
    // long alignedpointerToRaw = pointerToRaw & ~0x1ff;
    // long sizeOfRaw = section.get(SIZE_OF_RAW_DATA);
    // long readsize = ((pointerToRaw + sizeOfRaw) + filealign - 1) & ~(filealign - 1)) - alignedpointerToRaw;
    // readsize = min(readsize, (sizeOfRaw + 0xfff) & ~0xfff);
    // long virtsize = section.get(VIRTUAL_SIZE);
    //
    // if (virtsize)
    // {
    //     readsize = min(readsize, (virtsize + 0xfff) & ~0xfff);
    // }

    let file_alignment = file_alignment as usize;
    let size_of_raw_data = section.size_of_raw_data() as usize;
    let virtual_size = section.virtual_size() as usize;
    let read_size = {
        let read_size =
            ((section.pointer_to_raw_data() as usize + size_of_raw_data + file_alignment - 1)
                & !(file_alignment - 1))
                - aligned_pointer_to_raw_data(section.pointer_to_raw_data() as usize);
        cmp::min(read_size, round_size(size_of_raw_data))
    };

    if virtual_size == 0 {
        read_size
    } else {
        cmp::min(read_size, round_size(virtual_size))
    }
}

fn rva2offset<T: PESectionTable>(rva: usize, section: &T) -> usize {
    (rva - section.virtual_address() as usize)
        + aligned_pointer_to_raw_data(section.pointer_to_raw_data() as usize)
}

fn is_in_section<T: PESectionTable>(rva: usize, section: &T, file_alignment: u32) -> bool {
    let section_rva = section.virtual_address() as usize;
    is_in_range(
        rva,
        section_rva,
        section_rva + section_read_size(section, file_alignment),
    )
}

pub fn find_raw_offset<T: PESectionTable>(
    rva: usize,
    sections: &[T],
    file_alignment: u32,
) -> Option<usize> {
    for (i, section) in sections.iter().enumerate() {
        debug!(
            "Checking {} for {:#x} ∈ {:#x}..{:#x}",
            section.name().unwrap_or(""),
            rva,
            section.virtual_address(),
            section.virtual_address().wrapping_add(section.virtual_size())
        );
        if is_in_section(rva, section, file_alignment) {
            let offset = (section.pointer_to_raw_data() as usize)
                .wrapping_add(rva.wrapping_sub(section.virtual_address() as usize));

            debug!(
                "Found in section {}({}), remapped into offset {:#x}",
                section.name().unwrap_or(""),
                i,
                offset
            );
            return Some(offset);
        }
    }
    None
}

pub fn find_offset<T: PESectionTable>(
    rva: usize,
    sections: &[T],
    file_alignment: u32,
    opts: &options::ParseOptions,
) -> Option<usize> {
    if opts.resolve_rva {
        for (i, section) in sections.iter().enumerate() {
            debug!(
                "Checking {} for {:#x} ∈ {:#x}..{:#x}",
                section.name().unwrap_or(""),
                rva,
                section.virtual_address(),
                section.virtual_address() + section.virtual_size()
            );
            if is_in_section(rva, section, file_alignment) {
                let offset = rva2offset(rva, section);
                debug!(
                    "Found in section {}({}), remapped into offset {:#x}",
                    section.name().unwrap_or(""),
                    i,
                    offset
                );
                return Some(offset);
            }
        }
        None
    } else {
        Some(rva)
    }
}

pub fn find_offset_or<T: PESectionTable>(
    rva: usize,
    sections: &[T],
    file_alignment: u32,
    opts: &options::ParseOptions,
    msg: &str,
) -> error::Result<usize> {
    find_offset(rva, sections, file_alignment, opts)
        .ok_or_else(|| error::Error::Malformed(msg.to_string()))
}

pub fn try_name<'a, T: PESectionTable>(
    bytes: &'a [u8],
    rva: usize,
    sections: &[T],
    file_alignment: u32,
    opts: &options::ParseOptions,
) -> error::Result<&'a str> {
    match find_offset(rva, sections, file_alignment, opts) {
        Some(offset) => Ok(bytes.pread::<&str>(offset)?),
        None => Err(error::Error::Malformed(format!(
            "Cannot find name from rva {:#x} in sections: {:?}",
            rva, sections
        ))),
    }
}

pub fn get_data<'a, U, T>(
    bytes: &'a [u8],
    sections: &[U],
    directory: DataDirectory,
    file_alignment: u32,
) -> error::Result<T>
where
    T: scroll::ctx::TryFromCtx<'a, scroll::Endian, Error = scroll::Error>,
    U: PESectionTable,
{
    get_data_with_opts(
        bytes,
        sections,
        directory,
        file_alignment,
        &options::ParseOptions::default(),
    )
}

pub fn get_data_with_opts<'a, U, T>(
    bytes: &'a [u8],
    sections: &[U],
    directory: DataDirectory,
    file_alignment: u32,
    opts: &options::ParseOptions,
) -> error::Result<T>
where
    T: scroll::ctx::TryFromCtx<'a, scroll::Endian, Error = scroll::Error>,
    U: PESectionTable,
{
    let rva = directory.virtual_address as usize;
    let offset = find_offset(rva, sections, file_alignment, opts)
        .ok_or_else(|| error::Error::Malformed(directory.virtual_address.to_string()))?;
    let result: T = bytes.pread_with(offset, scroll::LE)?;
    Ok(result)
}

pub(crate) fn pad(length: usize, alignment: Option<usize>) -> Option<Vec<u8>> {
    match alignment {
        Some(alignment) => {
            let overhang = length % alignment;
            if overhang != 0 {
                let repeat = alignment - overhang;
                Some(vec![0u8; repeat])
            } else {
                None
            }
        }
        None => None,
    }
}
