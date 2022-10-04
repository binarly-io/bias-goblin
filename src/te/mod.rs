use scroll::Pread;

use crate::error;
use crate::pe::relocation::BaseRelocations;
use crate::pe::utils;

use self::header::SIZEOF_TE_HEADER;

pub mod data_directories;
pub mod debug;
pub mod header;
pub mod section_table;

#[derive(Debug)]
pub struct TE<'a> {
    pub header: header::Header,
    pub sections: Vec<section_table::SectionTable>,
    pub debug_data: Option<debug::DebugData<'a>>,
}

impl<'a> TE<'a> {
    pub fn parse(bytes: &'a [u8]) -> error::Result<Self> {
        let header = header::Header::parse(bytes)?;

        log::debug!("{:#?}", header);

        let mut offset = header::SIZEOF_TE_HEADER;
        let sections = header.sections(bytes, &mut offset)?;
        let mut debug_data = None;

        if let Some(debug_table) = *header.data_directories.get_debug_table() {
            let image_debug_directory = debug::ImageDebugDirectory::parse(
                bytes,
                debug_table,
                &sections,
                0x10,
            )?;

            // NOTE: we need to adjust the pointer to raw data
            let codeview_pdb70_debug_info = debug::CodeviewPDB70DebugInfo::parse(
                bytes,
                &debug::ImageDebugDirectory {
                    pointer_to_raw_data: image_debug_directory.pointer_to_raw_data
                        .wrapping_sub(header.stripped_size as u32)
                        .wrapping_add(SIZEOF_TE_HEADER as u32),
                    ..image_debug_directory
                },
            )?;

            debug_data = Some(debug::DebugData {
                image_debug_directory,
                codeview_pdb70_debug_info,
            });
        }

        Ok(Self {
            header,
            sections,
            debug_data,
        })
    }

    pub fn base_relocations(&self, bytes: &'a [u8]) -> Option<BaseRelocations<'a>> {
        let dds = self.header.data_directories;
        let relocs = dds.get_base_relocation_table().as_ref()?;

        let offset = utils::find_raw_offset(relocs.virtual_address as usize, &self.sections, 1)?;

        let reloc_bytes = bytes.pread_with(offset, relocs.size as usize).ok()?;

        BaseRelocations::parse(reloc_bytes).ok()
    }

    pub fn adjust_offset(&self, offset: usize) -> usize {
        offset
            .wrapping_sub(self.header.stripped_size as usize)
            .wrapping_add(SIZEOF_TE_HEADER)
    }

    pub fn entry_point(&self) -> u64 {
        self.image_base()
            .wrapping_add(self.header.address_of_entry_point as u64)
    }

    pub fn image_base(&self) -> u64 {
        self.header.image_base
    }
}
