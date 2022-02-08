use crate::error;
use scroll::{ctx, Pwrite, Pread};

pub use crate::pe::data_directories::{DataDirectory, SIZEOF_DATA_DIRECTORY};

pub const NUM_DATA_DIRECTORIES: usize = 2;
pub const SIZEOF_DATA_DIRECTORIES: usize = 2 * SIZEOF_DATA_DIRECTORY;

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct DataDirectories {
    base_relocation: Option<DataDirectory>,
    debug: Option<DataDirectory>,
}

impl DataDirectories {
    fn parse_single(bytes: &[u8], offset: &mut usize) -> Result<Option<DataDirectory>, scroll::Error> {
        let dir = bytes.gread_with::<DataDirectory>(offset, scroll::LE)?;
        if dir.virtual_address == 0 && dir.size == 0 {
            Ok(None)
        } else {
            Ok(Some(dir))
        }
    }

    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        Ok(Self {
            base_relocation: Self::parse_single(bytes, offset)?,
            debug: Self::parse_single(bytes, offset)?,
        })
    }

    pub fn get_base_relocation_table(&self) -> &Option<DataDirectory> {
        &self.base_relocation
    }

    pub fn get_debug_table(&self) -> &Option<DataDirectory> {
        &self.debug
    }
}

impl ctx::SizeWith<scroll::Endian> for DataDirectories {
    fn size_with(_ctx: &scroll::Endian) -> usize {
        SIZEOF_DATA_DIRECTORIES
    }
}

impl ctx::TryIntoCtx<scroll::Endian> for DataDirectories {
    type Error = scroll::Error;

    fn try_into_ctx(self, bytes: &mut [u8], ctx: scroll::Endian) -> Result<usize, Self::Error> {
        let offset = &mut 0;
        let default = DataDirectory::default();

        bytes.gwrite_with(
            self.base_relocation.as_ref().unwrap_or(&default),
            offset,
            ctx,
        )?;
        bytes.gwrite_with(self.debug.as_ref().unwrap_or(&default), offset, ctx)?;

        Ok(SIZEOF_DATA_DIRECTORIES)
    }
}

impl ctx::IntoCtx<scroll::Endian> for DataDirectories {
    fn into_ctx(self, bytes: &mut [u8], ctx: scroll::Endian) {
        bytes.pwrite_with(self, 0, ctx).unwrap();
    }
}

impl<'a> ctx::TryFromCtx<'a, scroll::Endian> for DataDirectories {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _ctx: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let dirs = Self {
            base_relocation: Self::parse_single(from, offset)?,
            debug: Self::parse_single(from, offset)?,
        };
        Ok((dirs, SIZEOF_DATA_DIRECTORIES))
    }
}
