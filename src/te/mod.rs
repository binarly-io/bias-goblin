use crate::error;

pub mod debug;
pub mod header;
pub mod data_directories;
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
            debug_data = Some(debug::DebugData::parse(
                bytes,
                debug_table,
                &sections,
                0x10,
            )?);
        }

        Ok(Self {
            header,
            sections,
            debug_data,
        })
    }

    pub fn entry_point(&self) -> u64 {
        self.image_base()
            .wrapping_add(self.header.address_of_entry_point as u64)
    }

    pub fn image_base(&self) -> u64 {
        self.header.image_base
    }
}
