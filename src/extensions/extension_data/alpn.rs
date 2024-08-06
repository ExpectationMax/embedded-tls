use heapless::Vec;

use crate::{
    buffer::CryptoBuffer,
    extensions::ExtensionType,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Protocol<'a> {
    pub name: &'a str,
}

impl<'a> Protocol<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Protocol<'a>, ParseError> {
        let name_len = buf.read_u16()?;
        let name = buf.slice(name_len as usize)?.as_slice();

        // RFC 6066, Section 3.  Server Name Indication
        // The hostname is represented as a byte
        // string using ASCII encoding without a trailing dot.
        if name.is_ascii() {
            Ok(Protocol {
                name: core::str::from_utf8(name).map_err(|_| ParseError::InvalidData)?,
            })
        } else {
            Err(ParseError::InvalidData)
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u8_length(|buf| buf.extend_from_slice(self.name.as_bytes()))
            .map_err(|_| TlsError::EncodeError)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ALPNList<'a, const N: usize> {
    pub protocol_list: Vec<Protocol<'a>, N>,
}

impl<'a> ALPNList<'a, 1> {
    pub fn single(protocol_name: &'a str) -> Self {
        let mut protocol_list = Vec::<_, 1>::new();

        protocol_list
            .push(Protocol {
                name: protocol_name,
            })
            .unwrap();

        ALPNList { protocol_list }
    }
}

impl<'a, const N: usize> ALPNList<'a, N> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<ALPNList<'a, N>, ParseError> {
        let data_length = buf.read_u16()? as usize;

        Ok(Self {
            protocol_list: buf.read_list::<_, N>(data_length, Protocol::parse)?,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for name in &self.protocol_list {
                name.encode(buf)?;
            }

            Ok(())
        })
    }
}
