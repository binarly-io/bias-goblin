use scroll::{ctx, Pread, Pwrite};

use crate::error;

pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
pub const WIN_CERT_TYPE_EFI_PKCS115: u16 = 0x0EF0;
pub const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0EF1;

#[derive(Debug, Copy, Clone, PartialEq, Default, Pread, Pwrite)]
#[repr(C)]
pub struct WinCertificateHeader {
    pub dw_length: u32,
    pub w_revision: u16,
    pub w_certificate_type: u16,
}

#[derive(Debug, Copy, Clone, PartialEq, Default)]
#[repr(C)]
pub struct WinCertificate<'a> {
    pub header: WinCertificateHeader,
    pub bytes: &'a [u8],
}

impl<'a> ctx::TryFromCtx<'a, scroll::Endian> for WinCertificate<'a> {
    type Error = error::Error;

    fn try_from_ctx(from: &'a [u8], ctx: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let header = from.gread_with::<WinCertificateHeader>(offset, ctx)?;
        if (header.dw_length as usize) < *offset {
            Err(error::Error::Malformed(
                "dw_length field in certificate header is smaller than header size".into(),
            ))
        } else {
            let bytes = from.gread_with::<&'a [u8]>(offset, header.dw_length as usize - *offset)?;
            let _pad = from.gread_with::<&'a [u8]>(offset, header.dw_length as usize % 8)?;
            let cert = Self { header, bytes };
            Ok((cert, *offset))
        }
    }
}

impl<'a> ctx::TryIntoCtx<scroll::Endian> for WinCertificate<'a> {
    type Error = scroll::Error;

    fn try_into_ctx(self, bytes: &mut [u8], ctx: scroll::Endian) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        bytes.gwrite_with(self.header, offset, ctx)?;
        bytes.gwrite_with(self.bytes, offset, ())?;

        Ok(*offset)
    }
}

#[derive(Default, Clone)]
pub struct WinCertificates<'a> {
    offset: usize,
    bytes: &'a [u8],
}

impl<'a> WinCertificates<'a> {
    pub fn parse(bytes: &'a [u8]) -> error::Result<WinCertificates<'a>> {
        Ok(WinCertificates { offset: 0, bytes })
    }
}

impl<'a> Iterator for WinCertificates<'a> {
    type Item = WinCertificate<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let cert = self
            .bytes
            .gread_with::<WinCertificate>(&mut self.offset, scroll::LE)
            .ok()?;

        Some(cert)
    }
}

#[cfg(test)]
mod tests {
    use crate::pe::PE;

    #[test]
    fn parse_certs_table() {
        let file = include_bytes!("/tmp/HelloWorld-MultiCerts.efi");
        let file = &file[..];
        let pe = PE::parse(file).unwrap();

        let certs = pe.certificates(file).unwrap();

        for cert in certs {
            assert_eq!(cert.header.dw_length, 1684);
            assert_eq!(cert.header.w_revision, 512);
            assert_eq!(cert.header.w_certificate_type, 2);
        }
    }
}
