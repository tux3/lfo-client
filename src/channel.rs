use anyhow::{bail, Result};
use byteorder::{ReadBytesExt, LE};
use std::io::Cursor;
use strum_macros::{AsRefStr, Display};
use tracing::{debug, error, info, trace, warn};

#[repr(u16)]
#[derive(Eq, PartialEq, Debug, Copy, Clone, AsRefStr, Display)]
pub enum ChannelDataFormatTags {
    Other(u16),
    FormatTags,
    FormatTagsNonDiff,
}

#[derive(Eq, PartialEq, Debug, Clone)]
/// Yeah boi!
pub struct DownloadRecord {
    pub lfo_host: String,
    pub remote_path: String,
    pub dst_filename: String,
    pub version: String,
    pub hash: Vec<u8>,
}

impl std::fmt::Display for DownloadRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadRecord")
            .field("lfo_host", &self.lfo_host)
            .field("remote_path", &self.remote_path)
            .field("dst_filename", &self.dst_filename)
            .field("version", &self.version)
            .field("hash", &hex::encode(&self.hash))
            .finish()
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ChannelDownloadMetadata {
    pub records: Vec<DownloadRecord>,
}

/// There are really many different channel formats contained in channel files
/// This only partially parses a couple that we care about to extract relevant info
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Channel {
    pub magic: u32,
    pub unk0: u16,
    pub channel_id: u16,
    pub unk2: u16,
    pub format_tags: ChannelDataFormatTags, // Can be 0x1 or 0x18
    // 0xC
    pub version0: u32,
    pub version1: u32,
    // 0x14: Header is variable size, but the smallest ends at 0x14

    // The following fields depend on channel_id
    // (Since we don't support most of them anyways, it's just Options instead of a proper enum)
    pub download_metadata: Option<ChannelDownloadMetadata>,
}

fn validate_format_tags(
    reader: &mut Cursor<&[u8]>,
    format_tags: ChannelDataFormatTags,
) -> Result<()> {
    if let ChannelDataFormatTags::Other(_) = format_tags {
        return Ok(());
    }

    let data_len = reader.get_ref().len();
    loop {
        let offset1 = reader.read_u32::<LE>()?;
        let offset2 = reader.read_u32::<LE>()?;
        if offset1 as usize >= data_len {
            bail!(
                "Invalid offset1 0x{:x} (file size 0x{:x})",
                offset1,
                data_len
            )
        }
        if offset2 != 0 && (offset2 <= 7 || offset2 as usize >= data_len - 8) {
            bail!(
                "Invalid offset2 0x{:x} (file size 0x{:x})",
                offset2,
                data_len
            )
        }

        unimplemented!()
    }
}

impl TryFrom<&Vec<u8>> for Channel {
    type Error = anyhow::Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<&[u8]> for Channel {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < 0x14 {
            bail!("Channel file too small");
        }
        trace!("Channel file is 0x{:x} bytes", data.len());
        // We don't bother checking the hash against the channel record, downloads are over TLS,
        // and we don't really want to keep passing the record around just for this

        let mut reader = Cursor::new(data);
        let magic = reader.read_u32::<LE>()?;
        let unk0 = reader.read_u16::<LE>()?;
        let channel_id = reader.read_u16::<LE>()?;
        let unk2 = reader.read_u16::<LE>()?;
        let format_tags = reader.read_u16::<LE>()?;
        let format_tags = match format_tags {
            0x01 => ChannelDataFormatTags::FormatTags,
            0x18 => ChannelDataFormatTags::FormatTagsNonDiff,
            n => ChannelDataFormatTags::Other(n),
        };
        let version0 = reader.read_u32::<LE>()?;
        let version1 = reader.read_u32::<LE>()?;
        if version0 >= version1 {
            bail!("Inconsistent channel 'version' fields")
        }

        if format_tags == ChannelDataFormatTags::FormatTags && data.len() < 0x23 {
            bail!("Channel file too small (CHANNEL_DATA_FORMAT_TAGS)")
        } else if format_tags == ChannelDataFormatTags::FormatTagsNonDiff && data.len() < 0x1B {
            bail!("Channel file too small (CHANNEL_DATA_FORMAT_TAGS_NONDIFF)")
        }

        validate_format_tags(&mut reader, format_tags)?;

        let mut chan = Self {
            magic,
            unk0,
            channel_id,
            unk2,
            format_tags,
            version0,
            version1,
            download_metadata: None,
        };

        if let ChannelDataFormatTags::Other(0x6) = format_tags {
            info!("Channel seems to contain download metadata, parsing");
            parse_channel_download_metadata(&mut chan, data)?;
        }

        Ok(chan)
    }
}

fn read_channel_buf_at(payload: &[u8], len: u16, off: u32) -> Result<Vec<u8>> {
    let beg = off as usize;
    let end = off as usize + len as usize;
    if payload.len() < end {
        bail!(
            "Trying to read {:#x} string bytes at {:#x}, but inner payload is only {:#x} bytes",
            len,
            off,
            payload.len()
        )
    }
    let str_slice = &payload[beg..end];
    Ok(str_slice.into())
}

fn read_channel_buf_from_len_off(payload: &[u8], reader: &mut Cursor<&[u8]>) -> Result<Vec<u8>> {
    let len = reader.read_u16::<LE>()?;
    let off = reader.read_u32::<LE>()?;
    read_channel_buf_at(payload, len, off)
}

fn read_channel_string_from_len_off(payload: &[u8], reader: &mut Cursor<&[u8]>) -> Result<String> {
    let buf = read_channel_buf_from_len_off(payload, reader)?;
    Ok(String::from_utf8(buf)?)
}

fn parse_channel_download_metadata(chan: &mut Channel, full_data: &[u8]) -> Result<()> {
    // Header is more of less variable size, but 0x14 is the 'lowest common denominator'
    let outer_hdr_size = 0x14;
    // All the offsets in the metadata assume just after the header is the base
    let data = &full_data[outer_hdr_size..];
    let mut reader = Cursor::new(data);

    // Don't know what to do with these yet
    let _ = reader.read_u16::<LE>()?;
    let _ = reader.read_u32::<LE>()?;
    let _ = reader.read_u32::<LE>()?;

    let maybe_num_records = reader.read_u32::<LE>()?;
    // In the one payload I looked at, this happens to be the prev field - 1. Unclear, ignoring it for now.
    let _unk_num = reader.read_u32::<LE>()?;

    // We have this array of offsets that seems to be followed immediately by a "data" section,
    // where we have the LFO DNS string and then strings/data for the download records
    // So I can't say for sure whether this is the offset of the end of the "offsets array" section,
    // the start of what I call the "data" section, or the offset to the LFO DNS string
    // (that last one seems unlikely, since it's not null-terminated and there's no size here)
    let offsets_array_end = reader.read_u32::<LE>()?;

    debug!(
        "Expecting maybe {} download records from header",
        maybe_num_records
    );
    // This parses the "offsets array", each entry is one DL record, but it only contains
    // offsets to the actual strings/data, which are packed in the data section at the end
    let mut records = Vec::new();
    let mut seen_last = false;
    for i in 0..maybe_num_records {
        trace!("Parsing download record {}", i);
        // Each entry is 0x3C bytes

        // These asserts only passed on one channel file, but the values don't seem to be too important
        let _unk_const_8 = reader.read_u32::<LE>()?;
        //assert_eq!(unk_const_8, 8);
        let _maybe_ev_id = reader.read_u32::<LE>()?;
        //assert_eq!(maybe_ev_id, 0x308005DF);

        let lfo_host = read_channel_string_from_len_off(data, &mut reader)?;

        let unk_const_c = reader.read_u32::<LE>()?;
        assert_eq!(unk_const_c, 0xC);
        let unk_const_1bb = reader.read_u16::<LE>()?;
        assert_eq!(unk_const_1bb, 0x1BB);

        let remote_path = read_channel_string_from_len_off(data, &mut reader)?;

        let unk_const_a = reader.read_u32::<LE>()?;
        assert_eq!(unk_const_a, 0xA);
        let dst_filename = read_channel_string_from_len_off(data, &mut reader)?;

        let unk_const_a = reader.read_u32::<LE>()?;
        assert_eq!(unk_const_a, 0xA);
        let hash1 = read_channel_buf_from_len_off(data, &mut reader)?;

        let unk_const_a = reader.read_u32::<LE>()?;
        assert_eq!(unk_const_a, 0xA);
        let hash2 = read_channel_buf_from_len_off(data, &mut reader)?;
        if hash1 != hash2 {
            warn!(
                "Download record has different hash1 and hash2 values, we may be parsing it wrong"
            );
        }

        let unk_const_a = reader.read_u32::<LE>()?;
        assert_eq!(unk_const_a, 0xA);
        let byte_field1 = read_channel_buf_from_len_off(data, &mut reader)?;

        let unk_const_a = reader.read_u32::<LE>()?;
        assert_eq!(unk_const_a, 0xA);
        let byte_field2 = read_channel_buf_from_len_off(data, &mut reader)?;
        assert_eq!(byte_field1, byte_field2);
        assert_eq!(byte_field1, &[0x00]); // Don't ask me why, I have not the faintest clue

        let unk_const_a = reader.read_u32::<LE>()?;
        assert_eq!(unk_const_a, 0xA);
        let version = read_channel_string_from_len_off(data, &mut reader)?;

        let unk_last_field = reader.read_u32::<LE>()?;
        match unk_last_field {
            0x12 => {
                if seen_last {
                    error!("Channel seem to have two 'last' download records, per the last field?");
                }
            } // All records we've seen, except the last
            0x00 => seen_last = true,
            n => error!(
                "Unexpected value {:#X} for last field of channel download record",
                n
            ),
        }

        trace!("Parsed record {} {} {}", dst_filename, remote_path, version);
        records.push(DownloadRecord {
            lfo_host,
            remote_path,
            dst_filename,
            version,
            hash: hash2,
        });
    }
    if !seen_last {
        error!("Last channel record did not end with the expected last field");
    }

    let cur_pos = data.len() - reader.remaining_slice().len();
    if cur_pos != offsets_array_end as usize {
        error!(
            "Expected download record offsets array to end at {:#x}, but stopped at {:#x}",
            offsets_array_end, cur_pos
        );
    }

    chan.download_metadata = Some(ChannelDownloadMetadata { records });
    Ok(())
}
