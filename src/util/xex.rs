use std::{
    borrow::Cow,
    cmp::min,
    collections::{btree_map::Entry, BTreeMap},
    fs,
    num::NonZeroU64,
};

use anyhow::{anyhow, bail, ensure, Result};
use lzxd::Lzxd;
use memchr::memmem;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use object::{
    endian,
    read::pe::PeFile32,
    write::{SectionId, SymbolId},
    Architecture, BinaryFormat, ComdatKind, Endianness, Object, ObjectSection, RelocationFlags,
    SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use typed_path::{Utf8NativePathBuf, Utf8UnixPath};

use crate::{
    analysis::{cfa::SectionAddress, read_u32},
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol,
        ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjSymbolScope,
        SectionIndex as ObjSectionIndex, SectionIndex, SymbolIndex as ObjSymbolIndex, SymbolIndex,
    },
    util::{
        config::is_auto_label,
        crypto::decrypt_aes128_cbc_no_padding,
        xex_imports::replace_ordinal,
    },
};

// quick and ez ways to read data from a block of bytes
pub fn read_halfword(data: &Vec<u8>, index: usize) -> u16 {
    return u16::from_be_bytes([data[index], data[index + 1]]);
}

pub fn read_word(data: &Vec<u8>, index: usize) -> u32 {
    return u32::from_be_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]]);
}

// ----------------------------------------------------------------------
// BASEFILEFORMAT
// ----------------------------------------------------------------------

pub struct BasicCompression {
    pub data_size: u32,
    pub zero_size: u32,
}

pub struct NormalCompression {
    pub window_size: u32,
    pub block_size: u32,
    pub block_hash: [u8; 20],
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum XexEncryption {
    No = 0,
    Yes = 1,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum XexCompression {
    None = 0,
    Raw = 1,
    Compressed = 2,
    DeltaCompressed = 3,
}

pub struct BaseFileFormat {
    pub encryption: XexEncryption,
    pub compression: XexCompression,
    pub basics: Vec<BasicCompression>,
    pub normal: Option<NormalCompression>,
}

impl BaseFileFormat {
    fn parse(data: &Vec<u8>) -> Result<Self> {
        let encryption = XexEncryption::try_from(read_halfword(&data, 0))?;
        let compression = XexCompression::try_from(read_halfword(&data, 2))?;
        let mut basics: Vec<BasicCompression> = vec![];
        let mut normal = None;
        match compression {
            XexCompression::None => {}
            XexCompression::Raw => {
                let count = (data.len() - 4) / 8;
                for i in 0..count {
                    basics.push(BasicCompression {
                        data_size: read_word(&data, 4 + i * 8),
                        zero_size: read_word(&data, 8 + i * 8),
                    });
                }
            }
            XexCompression::Compressed | XexCompression::DeltaCompressed => {
                normal = Some(NormalCompression {
                    window_size: read_word(&data, 4),
                    block_size: read_word(&data, 8),
                    block_hash: data[12..32].try_into()?,
                });
            }
        }
        return Ok(Self { encryption, compression, basics, normal });
    }
}

// ----------------------------------------------------------------------
// IMPORTLIBRARIES
// ----------------------------------------------------------------------

pub struct ImportLibraries {
    pub libraries: Vec<ImportLibrary>,
}

pub struct ImportFunction {
    pub address: u32,
    pub ordinal: u32,
    pub thunk: u32,
}

pub struct ImportLibrary {
    pub name: String,
    pub records: Vec<u32>,
    pub functions: Vec<ImportFunction>,
}

impl ImportLibraries {
    fn parse(data: &Vec<u8>) -> Result<Self> {
        let string_size = read_word(&data, 0);
        let lib_count = read_word(&data, 4);

        // populate the string table
        let mut string_table: Vec<String> = vec![];
        let mut pos: usize = 8;
        let mut cur_str = String::new();
        let cap: usize = (string_size + 8) as usize;
        while pos < cap {
            if data[pos] != 0 {
                cur_str += &(data[pos] as char).to_string();
            } else {
                // the values in between strings SHOULD be just zeros
                // but some games have super small non-zero values (tomb raider legend)
                while data[pos + 1] < 5 && pos < cap - 1 {
                    pos += 1;
                }
                string_table.push(cur_str.clone());
                cur_str.clear();
            }
            pos += 1;
        }

        // actually parse the import libraries
        pos = cap;
        let mut libraries: Vec<ImportLibrary> = vec![];
        for _ in 0..lib_count {
            pos += 0x24;
            let name_idx = read_halfword(&data, pos) as usize;
            let count = read_halfword(&data, pos + 2) as usize;
            pos += 4;
            let lib_name = &string_table[name_idx];
            let mut records: Vec<u32> = vec![];
            for i in 0..count {
                records.push(read_word(data, pos + (i * 4)));
            }
            pos += count * 4;
            libraries.push(ImportLibrary {
                name: lib_name.clone(),
                records,
                functions: Vec::new(),
            });
        }
        return Ok(Self { libraries });
    }
}

// ----------------------------------------------------------------------
// RESOURCEINFO
// ----------------------------------------------------------------------

pub struct ResourceInfos {
    pub info: Vec<ResourceInfo>,
}

pub struct ResourceInfo {
    pub title_id: String,
    pub rsrc_start: u32,
    pub rsrc_end: u32,
}

impl ResourceInfos {
    pub fn parse(data: &Vec<u8>) -> Result<Self> {
        ensure!(
            data.len() % 16 == 0,
            "Resource info has unexpected length! (expected a multiple of 16)"
        );
        let mut info: Vec<ResourceInfo> = vec![];
        for (_, chunk) in data.chunks_exact(16).enumerate() {
            let title_id = String::from_utf8(chunk[0..8].to_vec())?;
            let rsrc_start = u32::from_be_bytes(chunk[8..12].try_into()?);
            let rsrc_end = rsrc_start + u32::from_be_bytes(chunk[12..16].try_into()?);
            info.push(ResourceInfo { title_id, rsrc_start, rsrc_end });
        }
        return Ok(Self { info });
    }
}

// ----------------------------------------------------------------------
// XEXHEADER
// ----------------------------------------------------------------------

// header documentation: https://free60.org/System-Software/Formats/XEX/
pub struct XexHeader {
    // magic u32 here - must be "XEX2"
    pub module_flags: u32,
    pub pe_offset: u32,
    // reserved u32 here, but it goes unused so who cares
    pub security_info_offset: u32,
}

impl XexHeader {
    fn parse(data: &Vec<u8>) -> Result<Self> {
        let magic = read_word(&data, 0);
        ensure!(magic == 0x58455832, "XEX2 magic header not found!");
        let module_flags = read_word(&data, 4);
        let pe_offset = read_word(&data, 8);
        // reserved is at data index 12, but it's unused so who cares
        let security_info_offset = read_word(&data, 16);
        return Ok(Self { module_flags, pe_offset, security_info_offset });
    }
}

// ----------------------------------------------------------------------
// STATICLIBRARY
// ----------------------------------------------------------------------

pub struct StaticLibrary {
    pub name: String,
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub qfe: u8,
    pub approval_type: u8,
}

// ----------------------------------------------------------------------
// XEXOPTIONALHEADERDATA
// ----------------------------------------------------------------------

pub struct XexOptionalHeaderData {
    // Vec<XexOptionalHeader>? should we keep the vector of optional headers we find?
    pub original_name: String,
    pub entry_point: u32,
    pub image_base: u32,
    pub file_timestamp: u32,
    pub resource_info: Option<ResourceInfos>,
    pub base_file_format: Option<BaseFileFormat>,
    // PatchDescriptor
    pub static_libs: Vec<StaticLibrary>,
    pub import_libs: Option<ImportLibraries>,
}

impl XexOptionalHeaderData {
    fn parse(data: &Vec<u8>) -> Result<Self> {
        // read in the optional headers
        let num_optional_headers = read_word(&data, 20);
        let mut opt_headers: Vec<XexOptionalHeader> = vec![];
        for n in 0..num_optional_headers {
            opt_headers.push(XexOptionalHeader::new(data, (24 + n * 8) as usize));
        }

        let mut original_name = String::new();
        let mut entry_point = 0;
        let mut image_base = 0;
        let mut file_timestamp = 0;
        let mut import_libs = None;
        let mut resource_info = None;
        let mut base_file_format = None;
        let mut static_libs: Vec<StaticLibrary> = vec![];

        // and now, process them
        for header in opt_headers {
            ensure!(!header.data.is_empty(), "No data found in optional header!");
            match header.id {
                XexOptionalHeaderID::ResourceInfo => {
                    resource_info = Some(ResourceInfos::parse(&header.data)?);
                }
                XexOptionalHeaderID::BaseFileFormat => {
                    base_file_format = Some(BaseFileFormat::parse(&header.data)?);
                }
                XexOptionalHeaderID::DeltaPatchDescriptor => {
                    log::debug!("TODO: handle patch descriptor");
                }
                XexOptionalHeaderID::BoundingPath => {
                    log::debug!("TODO: handle bounding path");
                }
                XexOptionalHeaderID::EntryPoint => {
                    entry_point = read_word(&header.data, 0);
                }
                XexOptionalHeaderID::ImageBaseAddress => {
                    image_base = read_word(&header.data, 0);
                }
                XexOptionalHeaderID::ImportLibraries => {
                    import_libs = Some(ImportLibraries::parse(&header.data)?);
                }
                XexOptionalHeaderID::OriginalPEName => {
                    // trim off the 0's
                    let mut name = header.data.clone();
                    if let Some(i) = name.iter().rposition(|&x| x != 0) {
                        let new_len = i + 1;
                        name.truncate(new_len);
                    }
                    original_name = String::from_utf8(name)?;
                }
                XexOptionalHeaderID::ChecksumTimestamp => {
                    file_timestamp = read_word(&header.data, 0);
                }
                XexOptionalHeaderID::StaticLibraries => {
                    let num_libs = header.data.len() / 16;
                    for i in 0..num_libs {
                        let start = i * 16;
                        let mut name = header.data[start..start + 8].to_vec();
                        name.retain(|&x| x != 0);
                        static_libs.push(StaticLibrary {
                            name: String::from_utf8(name)?,
                            major: read_halfword(&header.data, start + 8),
                            minor: read_halfword(&header.data, start + 10),
                            build: read_halfword(&header.data, start + 12),
                            qfe: header.data[start + 15],
                            approval_type: header.data[start + 14],
                        });
                    }
                }
                _ => {
                    log::warn!("unhandled header ID {:?}", header.id);
                }
            }
        }
        // at the very minimum, we should have a base file format, as that contains encryption/compression information
        ensure!(base_file_format.is_some(), "Base file format not found!");
        return Ok(Self {
            original_name,
            entry_point,
            image_base,
            file_timestamp,
            resource_info,
            base_file_format,
            static_libs,
            import_libs,
        });
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum XexOptionalHeaderID {
    ResourceInfo = 0x2FF,
    BaseFileFormat = 0x3FF,
    BaseReference = 0x405,
    DeltaPatchDescriptor = 0x5FF,
    BoundingPath = 0x80FF,
    DeviceID = 0x8105,
    OriginalBaseAddress = 0x10001,
    EntryPoint = 0x10100,
    ImageBaseAddress = 0x10201,
    ImportLibraries = 0x103FF,
    ChecksumTimestamp = 0x18002,
    EnabledForCallcap = 0x18102,
    EnabledForFastcap = 0x18200,
    OriginalPEName = 0x183FF,
    StaticLibraries = 0x200FF,
    TLSInfo = 0x20104,
    DefaultStackSize = 0x20200,
    DefaultFilesystemCacheSize = 0x20301,
    DefaultHeapSize = 0x20401,
    PageHeapSizeAndFlags = 0x28002,
    SystemFlags = 0x30000,
    Unknown30100 = 0x30100,
    ExecutionID = 0x40006,
    ServiceIDList = 0x401FF,
    TitleWorkspaceSize = 0x40201,
    GameRatings = 0x40310,
    LANKey = 0x40404,
    Xbox360Logo = 0x405FF,
    MultidiscMediaIDs = 0x406FF,
    AlternateTitleIDs = 0x407FF,
    AdditionalTitleMemory = 0x40801,
    ExportsByName = 0xE10402,
}

pub struct XexOptionalHeader {
    pub id: XexOptionalHeaderID,
    pub value: u32,
    pub data: Vec<u8>,
}

impl XexOptionalHeader {
    pub fn new(data: &Vec<u8>, index: usize) -> Self {
        let mut hdr = Self {
            id: XexOptionalHeaderID::try_from(read_word(data, index)).unwrap(),
            value: read_word(data, index + 4),
            data: Vec::new(),
        };

        let id_as_u32: u32 = hdr.id.into();
        let mask = id_as_u32 & 0xFF;
        if mask == 0xFF {
            // seek the binstream to hdr.value, read the word (that's your len)
            let len = read_word(data, hdr.value as usize);
            let start: usize = (hdr.value + 4) as usize;
            let end: usize = (hdr.value + len) as usize;
            hdr.data = data[start..end].to_vec();
        } else if mask < 2 {
            // data = value as a Vec<u8>
            // println!("for ID 0x{:X}, value = 0x{:X}", id_as_u32, hdr.value);
            hdr.data = data[index + 4..index + 8].to_vec();
        } else {
            let len = mask * 4;
            let start: usize = (hdr.value + 4) as usize;
            let end: usize = (hdr.value + len) as usize;
            hdr.data = data[start..end].to_vec();
        }
        return hdr;
    }
}

// ----------------------------------------------------------------------
// XEXLOADERINFO
// ----------------------------------------------------------------------

pub struct XexLoaderInfo {
    pub header_size: u32,
    pub image_size: u32,
    pub rsa_signature: [u8; 256],
    pub unknown: u32,
    pub image_flags: u32,
    pub load_address: u32,
    pub section_digest: [u8; 20],
    pub import_table_count: u32,
    pub import_table_digest: [u8; 20],
    pub media_id: [u8; 16],
    pub file_key: [u8; 16],
    pub export_table: u32,
    pub header_digest: [u8; 20],
    pub game_regions: u32,
    pub media_flags: u32,
}

impl XexLoaderInfo {
    fn parse(data: &Vec<u8>, security_offset: u32) -> Result<Self> {
        let mut pos = security_offset as usize;
        let header_size = read_word(&data, pos);
        let image_size = read_word(&data, pos + 4);
        pos += 8;
        let rsa_signature = data[pos..pos + 256].try_into()?;
        pos += 256;
        let unknown = read_word(&data, pos);
        let image_flags = read_word(&data, pos + 4);
        let load_address = read_word(&data, pos + 8);
        pos += 12;
        let section_digest = data[pos..pos + 20].try_into()?;
        pos += 20;
        let import_table_count = read_word(&data, pos);
        pos += 4;
        let import_table_digest = data[pos..pos + 20].try_into()?;
        pos += 20;
        let media_id = data[pos..pos + 16].try_into()?;
        pos += 16;
        let file_key = data[pos..pos + 16].try_into()?;
        pos += 16;
        let export_table = read_word(&data, pos);
        pos += 4;
        let header_digest = data[pos..pos + 20].try_into()?;
        pos += 20;
        let game_regions = read_word(&data, pos);
        let media_flags = read_word(&data, pos + 4);
        return Ok(Self {
            header_size,
            image_size,
            rsa_signature,
            unknown,
            image_flags,
            load_address,
            section_digest,
            import_table_count,
            import_table_digest,
            media_id,
            file_key,
            export_table,
            header_digest,
            game_regions,
            media_flags,
        });
    }
}

// ----------------------------------------------------------------------
// XEXSESSIONKEYS
// ----------------------------------------------------------------------
const RETAIL_KEY: [u8; 16] = [
    0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3, 0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91,
];
const DEVKIT_KEY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub struct XexSessionKeys {
    pub session_key_retail: [u8; 16],
    pub session_key_devkit: [u8; 16],
}

impl XexSessionKeys {
    fn derive_keys(file_key: &[u8; 16]) -> Result<Self> {
        let retail_derived_key: [u8; 16] =
            decrypt_aes128_cbc_no_padding(&RETAIL_KEY, file_key)?.try_into().unwrap();
        let devkit_derived_key: [u8; 16] =
            decrypt_aes128_cbc_no_padding(&DEVKIT_KEY, file_key)?.try_into().unwrap();
        // print!("Retail session key: ");
        // for k in retail_derived_key {
        //     print!("{:02X} ", k);
        // }
        // print!("\n");
        // print!("Devkit session key: ");
        // for k in devkit_derived_key {
        //     print!("{:02X} ", k);
        // }
        // print!("\n");
        return Ok(Self {
            session_key_retail: retail_derived_key,
            session_key_devkit: devkit_derived_key,
        });
    }
}

// ----------------------------------------------------------------------
// XEXINFO
// ----------------------------------------------------------------------

pub struct XexInfo {
    pub header: XexHeader,
    pub opt_header_data: XexOptionalHeaderData,
    pub loader_info: XexLoaderInfo,
    pub session_key: [u8; 16],
    pub is_dev_kit: bool,
    pub exe_bytes: Vec<u8>,
}

impl XexInfo {
    pub fn from_file(path: &Utf8NativePathBuf) -> Result<Self> {
        let std_path = path.to_path_buf();
        let data = fs::read(std_path).expect("Failed to read file");

        let xex_header = XexHeader::parse(&data)?;
        let xex_optional_header_data = XexOptionalHeaderData::parse(&data)?;
        let xex_loader_info = XexLoaderInfo::parse(&data, xex_header.security_info_offset)?;
        let xex_session_keys = XexSessionKeys::derive_keys(&xex_loader_info.file_key)?;
        let confirmed_session_key: [u8; 16];
        let is_dev_kit: bool;
        let exe_bytes: Vec<u8>;

        // this is where we'd parse xexsection related info...but it might not be needed?

        let pe_vec = &data[xex_header.pe_offset as usize..data.len()].to_vec();
        let bff = xex_optional_header_data.base_file_format.as_ref().unwrap();
        match XexInfo::try_get_exe(
            pe_vec,
            &xex_session_keys.session_key_retail,
            bff,
            xex_loader_info.image_size,
        ) {
            Ok(exe) => {
                // println!("This xex was built in retail mode!");
                confirmed_session_key = xex_session_keys.session_key_retail;
                is_dev_kit = false;
                exe_bytes = exe;
            }
            Err(_) => {
                match XexInfo::try_get_exe(
                    pe_vec,
                    &xex_session_keys.session_key_devkit,
                    bff,
                    xex_loader_info.image_size,
                ) {
                    Ok(exe) => {
                        // println!("This xex was built in devkit mode!");
                        confirmed_session_key = xex_session_keys.session_key_devkit;
                        is_dev_kit = true;
                        exe_bytes = exe;
                    }
                    Err(e) => return Err(e), // here until case 2 is implemented
                }
            }
        }

        return Ok(Self {
            header: xex_header,
            opt_header_data: xex_optional_header_data,
            loader_info: xex_loader_info,
            session_key: confirmed_session_key,
            is_dev_kit,
            exe_bytes,
        });
    }

    pub fn try_get_exe(
        exe_data: &Vec<u8>,
        session_key: &[u8; 16],
        bff: &BaseFileFormat,
        img_size: u32,
    ) -> Result<Vec<u8>> {
        let compressed: Cow<[u8]>;

        match bff.encryption {
            XexEncryption::No => {
                compressed = Cow::Borrowed(&exe_data);
            }
            XexEncryption::Yes => {
                compressed = Cow::Owned(decrypt_aes128_cbc_no_padding(&session_key, &exe_data)?);
            }
        }

        let mut pe_image: Vec<u8> = vec![];
        pe_image.resize(img_size as usize, 0);
        let mut pos_in: usize = 0;
        let mut pos_out: usize = 0;

        match bff.compression {
            XexCompression::Raw => {
                for bc in &bff.basics {
                    for i in 0..(bc.data_size as usize) {
                        if pos_in + i as usize >= compressed.len() {
                            break;
                        }
                        pe_image[i + pos_out] = compressed[pos_in + i];
                    }
                    pos_out += (bc.data_size + bc.zero_size) as usize;
                    pos_in += bc.data_size as usize;
                }
            }
            XexCompression::None | XexCompression::DeltaCompressed => {
                pe_image = compressed.to_vec();
            }
            XexCompression::Compressed => {
                let comp = bff.normal.as_ref().unwrap();
                let lzx_window = lzxd::WindowSize::KB32;
                let mut lzxd_state = Lzxd::new(lzx_window);
                let window_size = comp.window_size as usize;
                let mut current_block_size = comp.block_size as usize;

                while current_block_size != 0 {
                    if pos_in + current_block_size > compressed.len() {
                        bail!(
                            "LZX: block needs {} bytes at 0x{:X} but only {} remain",
                            current_block_size,
                            pos_in,
                            compressed.len() - pos_in
                        );
                    }
                    let block = &compressed[pos_in..pos_in + current_block_size];
                    pos_in += current_block_size;
                    if block.len() < 24 {
                        bail!("LZX: block too small for header: {} bytes", block.len());
                    }
                    let next_block_size = u32::from_be_bytes([
                        block[0], block[1], block[2], block[3],
                    ]) as usize;
                    let mut off = 24usize;
                    while off + 2 <= block.len() {
                        let chunk_len = u16::from_be_bytes([
                            block[off], block[off + 1],
                        ]) as usize;
                        off += 2;

                        if chunk_len == 0 {
                            break;
                        }

                        if off + chunk_len > block.len() {
                            bail!(
                                "LZX: sub-chunk at offset {} wants {} bytes but only {} remain",
                                off,
                                chunk_len,
                                block.len() - off
                            );
                        }
                        let chunk_data = &block[off..off + chunk_len];
                        off += chunk_len;
                        let expected =
                            min(window_size, pe_image.len().saturating_sub(pos_out));
                        if expected == 0 {
                            break;
                        }
                        let decompressed = lzxd_state
                            .decompress_next(chunk_data, expected)
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "LZX: decompress failed at pos_out=0x{:X} \
                                     (chunk_len={}, expected={}, block_off={}): {:?}",
                                    pos_out,
                                    chunk_len,
                                    expected,
                                    off - chunk_len,
                                    e
                                )
                            })?;

                        if decompressed.is_empty() {
                            bail!(
                                "LZX: decompression returned zero bytes at pos_out=0x{:X}",
                                pos_out
                            );
                        }

                        let copy_len = min(decompressed.len(), pe_image.len() - pos_out);
                        pe_image[pos_out..pos_out + copy_len]
                            .copy_from_slice(&decompressed[..copy_len]);
                        pos_out += copy_len;
                    }
                    current_block_size = next_block_size;
                }
                if pos_out == 0 {
                    bail!("LZX: produced zero output bytes");
                }
            }
        }

        ensure!(pe_image[0] == 'M' as u8 && pe_image[1] == 'Z' as u8, "This is not a valid exe!");

        // adjust the byte offsets, because virtual addresses have been thrown off in the initial exe reconstruction process
        let pe_file =
            PeFile32::parse(&*pe_image).expect("Failed to parse newly pulled out exe file");
        let mut pe_file_adjusted: Vec<u8> = vec![];
        let mut first_flag = false;

        for sec in pe_file.section_table().iter() {
            if !first_flag {
                for i in 0..sec.pointer_to_raw_data.get(endian::LittleEndian) {
                    pe_file_adjusted.push(pe_image[i as usize]);
                }
                first_flag = true;
            }
            // if this section is NOT bss (no uninitialized data)
            if (sec.characteristics.get(endian::LittleEndian) & 0x80) == 0 {
                assert_eq!(
                    pe_file_adjusted.len() as u32,
                    sec.pointer_to_raw_data.get(endian::LittleEndian),
                    "Unexpected PE size at this point!"
                );
                for j in 0..sec.size_of_raw_data.get(endian::LittleEndian) {
                    let offset = (j + sec.virtual_address.get(endian::LittleEndian)) as usize;
                    if offset >= pe_image.len() {
                        pe_file_adjusted.push(0);
                    } else {
                        pe_file_adjusted.push(pe_image[offset]);
                    }
                }
            }
        }
        return Ok(pe_file_adjusted);
    }
}

pub fn extract_exe(input: &Utf8NativePathBuf) -> Result<(String, Vec<u8>)> {
    println!("xex: {input}");
    let xex = XexInfo::from_file(input)?;
    // after this line, the XexInfo should have all of its relevant metadata parsed
    return Ok((xex.opt_header_data.original_name, xex.exe_bytes));
}

pub fn process_xex(path: &Utf8NativePathBuf) -> Result<ObjInfo> {
    // look at cmd\dol\split
    println!("xex: {path}");
    let xex = XexInfo::from_file(path)?;
    let obj_file = PeFile32::parse(&*xex.exe_bytes).expect("Failed to parse object file");
    let architecture = ObjArchitecture::PowerPc;
    let kind = ObjKind::Executable;
    let obj_name = xex.opt_header_data.original_name;

    let mut sections: Vec<ObjSection> = vec![];
    let mut section_indexes: Vec<Option<usize>> = vec![None /* ELF null section */];
    for section in obj_file.sections() {
        if section.size() == 0 {
            section_indexes.push(None);
            continue;
        }
        let section_name = section.name()?;
        let section_kind = match section.kind() {
            SectionKind::Text => ObjSectionKind::Code,
            SectionKind::Data => ObjSectionKind::Data,
            SectionKind::ReadOnlyData => ObjSectionKind::ReadOnlyData,
            SectionKind::UninitializedData => ObjSectionKind::Bss,
            // SectionKind::Other if section_name == ".comment" => ObjSectionKind::Comment,
            _ => {
                section_indexes.push(None);
                continue;
            }
        };
        section_indexes.push(Some(sections.len()));
        // because some exes like to give us data whose size < the virtual size
        let mut section_data = section.uncompressed_data()?.to_vec();
        section_data.resize(section.size() as usize, 0);
        // should we do anything with section.flags()? xex uses COFF
        sections.push(ObjSection {
            name: section_name.to_string(),
            kind: section_kind,
            address: section.address(),
            size: section.size(),
            data: section_data,
            align: section.align(),
            // exe indices start at 1...why? i hate you that's why
            elf_index: section.index().0 as ObjSectionIndex,
            // everything below this line doesn't really matter for the purposes of an xex
            relocations: Default::default(),
            virtual_address: None, // Loaded from section symbol
            file_offset: section.file_range().map(|(v, _)| v).unwrap_or_default(),
            section_known: true,
            splits: Default::default(),
        });
    }

    // Create object
    let mut obj = ObjInfo::new(kind, architecture, obj_name.to_string(), vec![], sections);
    obj.entry = NonZeroU64::new(obj_file.entry()).map(|n| n.get());

    // inspect the ImportLibraries
    // https://github.com/zeroKilo/XEXLoaderWV/blob/master/XEXLoaderWV/src/main/java/xexloaderwv/XEXHeader.java#L211
    let mut xex_libs = xex.opt_header_data.import_libs;
    // if we even have import libraries
    if let Some(imports) = xex_libs.as_mut() {
        // first, retrieve the ImportFunctions
        for lib in imports.libraries.iter_mut() {
            for record in lib.records.iter() {
                // so what needs to happen here:
                // record = a virtual memory address
                // get the value inside it, it should be something like (example: 01 00 01 94)
                // the last 3 bytes (00 01 94) is the ordinal, the first byte (01) is the itype
                // if 0, it's a func, if 1, it's a thunk

                let sec = obj.sections.at_address(*record)?.1;
                let offset_within_sec = record - sec.address as u32;
                let value = read_word(&sec.data, offset_within_sec as usize);
                let ordinal = value & 0xFFFF;
                let itype = value >> 24;
                match itype {
                    0 => {
                        lib.functions.push(ImportFunction { address: *record, ordinal, thunk: 0 });
                    }
                    1 => {
                        if let Some(func) = lib.functions.last_mut() {
                            // println!("Record 0x{:08X}, ordinal 0x{:04X}, thunk 0x{:08X}", func.address, ordinal, *record);
                            func.thunk = *record;
                        }
                    }
                    _ => {} // shouldn't ever reach this branch, will always be 0 or 1
                }
            }
        }

        let mut num_imps = 0;
        let mut num_thunks = 0;
        let mut min_imp_addr: Option<u32> = None;
        let mut max_imp_addr: Option<u32> = None;
        let mut min_api_addr: Option<u32> = None;
        let mut max_api_addr: Option<u32> = None;
        let mut captured_imps: Vec<u32> = vec![];

        // to unstrip an __imp_,
        // swap the endianness of the last two bytes (so 00 01 01 90 becomes 90 01 00 00, we only care about the last two bytes)
        // then slap an 80 at the end (90 01 00 80) - the 80 tells the system that we're importing by ordinal
        fn unstrip_imp(imp: &mut [u8]) {
            imp[0] = imp[3];
            imp[1] = imp[2];
            imp[2] = 0;
            imp[3] = 0x80;
        }
        fn add_imp(obj: &mut ObjInfo, name: String, addr: SectionAddress) -> Result<SymbolIndex> {
            return obj.add_symbol(
                ObjSymbol {
                    name,
                    address: addr.address as u64,
                    section: Some(addr.section),
                    size: 4,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    kind: ObjSymbolKind::Object,
                    ..Default::default()
                },
                false,
            );
        }
        // to unstrip a thunk,
        // you need the address of the __imp_ (i.e. __imp_XamInputGetCapabilities at 0x827103c4)
        // then add it into the first two words via an lis/addi
        // (example: XamInputGetCapabilities: 01 00 01 90 02 00 01 90 7D 69 03 A6 4E 80 04 20)
        // (change the first two words to lis/addi r11 to 0x827103c4: 3D 60 82 71 81 6B 03 C4)
        // (then it becomes: 3D 60 82 71 81 6B 03 C4 7D 69 03 A6 4E 80 04 20)
        fn unstrip_thunk(thunk: &mut [u8], imp_addr: u32) {
            thunk[0] = 0x3D;
            thunk[1] = 0x60;
            thunk[2] = ((imp_addr & 0xFF000000) >> 24) as u8;
            thunk[3] = ((imp_addr & 0xFF0000) >> 16) as u8;
            thunk[4] = 0x81;
            thunk[5] = 0x6B;
            thunk[6] = ((imp_addr & 0xFF00) >> 8) as u8;
            thunk[7] = (imp_addr & 0xFF) as u8;
        }
        fn add_thunk(obj: &mut ObjInfo, name: String, addr: SectionAddress) -> Result<SymbolIndex> {
            obj.known_functions.insert(addr, Some(0x10));
            obj.add_symbol(
                ObjSymbol {
                    name,
                    address: addr.address as u64,
                    section: Some(addr.section),
                    size: 0x10,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    kind: ObjSymbolKind::Function,
                    ..Default::default()
                },
                false,
            )
        }

        // now, process them (add funcs/symbols and unstrip)
        for lib in imports.libraries.iter() {
            // println!("Imports for {}:", lib.name);
            for func in lib.functions.iter() {
                // println!("  Func: addr 0x{:08X}, ordinal 0x{:04X}, thunk 0x{:08X}", func.address, func.ordinal, func.thunk);
                assert_ne!(func.address, 0, "Should not have an empty import func address!");
                min_imp_addr = Some(min_imp_addr.unwrap_or(func.address).min(func.address));
                max_imp_addr = Some(max_imp_addr.unwrap_or(func.address).max(func.address));

                let (sec_idx, sec) = obj.sections.at_address_mut(func.address)?;
                let lookup_name = replace_ordinal(&lib.name, func.ordinal as usize);
                let sym_name = format!("__imp_{}", lookup_name);

                let offset_within_sec: usize = func.address as usize - sec.address as usize;
                unstrip_imp(&mut sec.data[offset_within_sec..offset_within_sec + 4]);
                // println!("  Adding symbol {} at 0x{:08X}", sym_name, func.address);
                add_imp(&mut obj, sym_name, SectionAddress::new(sec_idx, func.address))?;
                captured_imps.push(func.address);
                num_imps += 1;

                if func.thunk != 0 {
                    min_api_addr = Some(min_api_addr.unwrap_or(func.thunk).min(func.thunk));
                    max_api_addr = Some(max_api_addr.unwrap_or(func.thunk).max(func.thunk));
                    // println!("thunk at 0x{:08X}", func.thunk);
                    // create a symbol/func for the thunk - will always be size 0x10
                    let (thunk_idx, thunk_sec) = obj.sections.at_address_mut(func.thunk)?;
                    let offset_within_sec: usize = func.thunk as usize - thunk_sec.address as usize;
                    unstrip_thunk(
                        &mut thunk_sec.data[offset_within_sec..offset_within_sec + 8],
                        func.address,
                    );
                    // println!("  Adding symbol {} at 0x{:08X}", lookup_name, func.thunk);
                    add_thunk(&mut obj, lookup_name, SectionAddress::new(thunk_idx, func.thunk))?;
                    num_thunks += 1;
                }
            }
        }

        // for SOME reason, microsoft can have imports/thunks that aren't referenced in the import libraries
        // but can be referenced in xidata later on
        // so, this block of code serves to search for and capture them
        if min_imp_addr.is_some() && max_imp_addr.is_some() {
            let min_addr = min_imp_addr.unwrap();
            let max_addr = max_imp_addr.unwrap();

            // i had to write things this way because of how rust handles borrowing...thank you rust, very cool
            let (import_idx, offset_within_sec) = {
                let (idx, sec) = obj.sections.at_address(min_addr)?;
                (idx, (min_addr - sec.address as u32) as usize)
            };
            let mut i = min_addr;
            loop {
                let data_idx = offset_within_sec + (i - min_addr) as usize;
                let cur_imp = {
                    let sec = &obj.sections[import_idx];
                    if data_idx >= sec.data.len() {
                        break;
                    }
                    read_word(&sec.data, data_idx)
                };
                if i > max_addr && cur_imp == 0 {
                    break;
                }

                if cur_imp != 0 && !captured_imps.contains(&i) {
                    let sym_name = format!(
                        "__imp_{}",
                        replace_ordinal(
                            &imports.libraries[((cur_imp & 0x00FF0000) >> 16) as usize].name,
                            (cur_imp & 0xFFFF) as usize
                        )
                    );
                    // println!("Found missing imp {} at 0x{:08X}", sym_name, i);
                    {
                        // obj borrowing scope moment
                        let sec = &mut obj.sections[import_idx];
                        unstrip_imp(&mut sec.data[data_idx..data_idx + 4]);
                    }
                    add_imp(&mut obj, sym_name, SectionAddress::new(import_idx, i))?;
                    num_imps += 1;
                }

                i += 4;
            }
        }
        if min_api_addr.is_some() && max_api_addr.is_some() {
            let min_addr = min_api_addr.unwrap();
            let max_addr = max_api_addr.unwrap();

            // i had to write things this way because of how rust handles borrowing...thank you rust, very cool
            let (thunk_idx, offset_within_sec) = {
                let (idx, sec) = obj.sections.at_address(min_addr)?;
                (idx, (min_addr - sec.address as u32) as usize)
            };

            let mut i = min_addr;
            loop {
                let data_idx = offset_within_sec + (i - min_addr) as usize;
                let cur_thunk = {
                    let sec = &obj.sections[thunk_idx];
                    if data_idx >= sec.data.len() {
                        break;
                    }
                    read_word(&sec.data, data_idx)
                };
                if i > max_addr && cur_thunk == 0 {
                    break;
                } else if i < max_addr && cur_thunk == 0 {
                    i += 4;
                    continue;
                }

                if cur_thunk != 0 {
                    let cur_addr = SectionAddress::new(thunk_idx, i);
                    if !obj.known_functions.contains_key(&cur_addr) {
                        let sym_name = replace_ordinal(
                            &imports.libraries[((cur_thunk & 0x00FF0000) >> 16) as usize].name,
                            (cur_thunk & 0xFFFF) as usize,
                        );
                        // println!("Found missing thunk {} at 0x{:08X}", sym_name, i);
                        let imp_name = format!("__imp_{}", sym_name);
                        let maybe_imp_sym = obj.symbols.by_name(&imp_name)?;
                        if maybe_imp_sym.is_some() {
                            // println!("found sym {}", maybe_imp_sym.unwrap().1.name);
                            unstrip_thunk(
                                &mut obj.sections[thunk_idx].data[data_idx..data_idx + 8],
                                maybe_imp_sym.unwrap().1.address as u32,
                            );
                        }
                        add_thunk(&mut obj, sym_name, cur_addr)?;
                        num_thunks += 1;
                    }
                }
                i += 0x10;
            }
        }
        log::info!("Found {} imps and {} import thunks from import data!", num_imps, num_thunks);
    }

    // add known function boundaries from pdata
    let (pdata_addr, pdata_data) = match obj.sections.by_name(".pdata")? {
        Some((idx, pdata_section)) => {
            (SectionAddress::new(idx, pdata_section.address as u32), pdata_section.data.clone())
        }
        None => return Err(anyhow!(".pdata section not found. Is that even possible for an xex?")),
    };

    let mut num = 0;
    for (i, chunk) in pdata_data.chunks_exact(8).enumerate() {
        let start_addr = u32::from_be_bytes(chunk[0..4].try_into()?);
        // if we encounter 0's, that's the end of usable pdata entries
        if start_addr == 0 {
            break;
        }

        // some metadata for this function, including function size
        let word = u32::from_be_bytes(chunk[4..8].try_into()?);
        // let num_prologue_insts = word & 0xFF; // The number of instructions in the function's prolog.
        let num_insts_in_func = (word >> 8) & 0x3FFFFF; // The number of instructions in the function.
        let func_type = word >> 30; // The function type.

        let this_entry_addr = pdata_addr + (i * 8) as u32;
        obj.add_symbol(
            ObjSymbol {
                name: format!("pdata@{:08X}", this_entry_addr.address),
                address: this_entry_addr.address as u64,
                section: Some(pdata_addr.section),
                size: 8,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
            false,
        )?;
        let section_addr = SectionAddress::new(obj.sections.at_address(start_addr)?.0, start_addr);
        obj.known_functions.insert(section_addr, Some(num_insts_in_func * 4));
        obj.pdata_funcs.push(section_addr);
        num += 1;

        // if func_type == 3, there's an 8 byte struct (with 2 words) just before the function start that contains exception data
        if func_type == 3 {
            // println!("Exception handler at {:08X}, record at {:08X}", start_addr - 8, start_addr - 4);
            obj.add_symbol(
                ObjSymbol {
                    name: format!("except_data_{:08X}", start_addr),
                    address: (start_addr - 8) as u64,
                    section: Some(section_addr.section),
                    size: 8,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    kind: ObjSymbolKind::Object,
                    ..Default::default()
                },
                false,
            )?;
            // word 1: the address of the function's exception handler
            if let Some(except_func) =
                read_u32(obj.sections.at_address(start_addr - 8)?.1, start_addr - 8)
            {
                let except_func_section =
                    SectionAddress::new(obj.sections.at_address(except_func)?.0, except_func);
                // check to see if the addr is already part of a known function - if it's not, add it to known_functions
                if let Entry::Vacant(e) = obj.known_functions.entry(except_func_section) {
                    e.insert(None);
                    num += 1;
                }
            } else {
                bail!("Invalid exception handler address listed at {}!", start_addr - 8)
            }
            // word 2: the address of the function's exception handler data record
            if let Some(except_record) =
                read_u32(obj.sections.at_address(start_addr - 4)?.1, start_addr - 4)
            {
                // exception handlers can have no record (a nullptr in the exception data)
                if except_record != 0 {
                    let except_record_section = SectionAddress::new(
                        obj.sections.at_address(except_record)?.0,
                        except_record,
                    );
                    obj.add_symbol(
                        ObjSymbol {
                            name: format!("except_record_{:08X}", start_addr),
                            address: except_record as u64,
                            section: Some(except_record_section.section),
                            size: 4,
                            size_known: false, // we don't know exactly how big this particular exception record may be
                            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                            kind: ObjSymbolKind::Object,
                            ..Default::default()
                        },
                        false,
                    )?;
                }
            } else {
                bail!("Invalid exception record address listed at {}!", start_addr - 4)
            }
        }
    }
    log::info!("Found {} known funcs from pdata!", num);

    // if this xex has an .xidata section, mark down the funcs in there
    if let Some((xidata_idx, xidata_sec)) = obj.sections.by_name(".xidata")? {
        let mut num_xidatas = 0;
        for (i, chunk) in xidata_sec.data.chunks_exact(16).enumerate() {
            if i == 0 {
                continue;
            } // the first entry appears to be all 0's...but is every xidata like this?
            let inst1 = u32::from_be_bytes(chunk[0..4].try_into()?);
            // if we've reached 0's, that's the end of usable xidata info
            if inst1 == 0 {
                break;
            }

            assert_eq!(inst1 & 0xFFFF0000, 0x3D600000, "First instruction MUST be an lis to r11!");
            let inst2 = u32::from_be_bytes(chunk[4..8].try_into()?);
            assert_eq!(
                inst2 & 0xFFFF0000,
                0x396B0000,
                "Second instruction MUST be an addi to r11!"
            );
            assert_eq!(
                u32::from_be_bytes(chunk[8..12].try_into()?),
                0x7d6903a6,
                "Third instruction MUST be mtspr CTR, r11!"
            );
            assert_eq!(
                u32::from_be_bytes(chunk[12..16].try_into()?),
                0x4e800420,
                "Fourth and final instruction MUST be bctr!"
            );

            let func_addr = (xidata_sec.address as usize + (i * 16)) as u32;
            // println!("This xidata func's address: 0x{:08X}", func_addr);
            obj.known_functions.insert(SectionAddress::new(xidata_idx, func_addr), Some(0x10));
            num_xidatas += 1;
        }
        log::info!("Found {} known funcs from xidata!", num_xidatas);
    }

    const RTL_CHECK_STACK: [u8; 40] = [
        // _RtlCheckStack
        0x7d, 0x83, 0x00, 0xd0, // _RtlCheckStack12
        0x7d, 0x6c, 0x00, 0xd0, 0x38, 0x0b, 0x0f, 0xff, 0x7c, 0x00, 0x66, 0x71, 0x4c, 0x81, 0x00,
        0x20, 0x7c, 0x2b, 0x0b, 0x78, 0x7c, 0x09, 0x03, 0xa6, 0x84, 0x0b, 0xf0, 0x00, 0x42, 0x00,
        0xff, 0xfc, 0x4e, 0x80, 0x00, 0x20,
    ];

    let mut api_syms: Vec<ObjSymbol> = vec![];
    for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
        let Some(pos) = memmem::find(&section.data, &RTL_CHECK_STACK) else {
            continue;
        };
        let start = SectionAddress::new(section_index, section.address as u32 + pos as u32);
        obj.known_functions.insert(start, Some(4));
        obj.known_functions.insert(start + 4, Some(36));
        api_syms.push(ObjSymbol {
            name: String::from("_RtlCheckStack"),
            address: start.address as u64,
            section: Some(start.section),
            size: 4,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            kind: ObjSymbolKind::Function,
            ..Default::default()
        });
        api_syms.push(ObjSymbol {
            name: String::from("_RtlCheckStack12"),
            address: (start.address + 4) as u64,
            section: Some(start.section),
            size: 36,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            kind: ObjSymbolKind::Function,
            ..Default::default()
        });
    }
    for sym in api_syms {
        obj.add_symbol(sym, false)?;
    }

    // .XBMOVIE: matches up with ground truth...but it's mostly a sea of 0's
    // .idata: partially zero'ed out and offsetted from ground truth in debug, completely gone from release
    //      xidata/its relevant info seems to be covered, making idata a non-issue...i guess?
    // .XBLD: zero'ed out in debug, completely gone from release
    // .reloc: zero'ed out regardless

    Ok(obj)
}

/// Build the set of `except_data_<suffix>` symbols (keyed by hex suffix, the
/// function VA) that are *genuine* PDATA_EH structs, as opposed to spurious
/// over-broad symbols left by a prior split run sitting on top of live code.
///
/// Must be called against the FULL (un-split) module so that the handler VA in
/// word1 can be resolved: the retail XEX shares a single `__CxxFrameHandler`
/// that lives in a different unit than most EH structs, so a per-split-object
/// `at_address` lookup would wrongly reject every cross-unit handler. A genuine
/// struct's word1 is a code-section VA (the handler); a spurious one's word1 is
/// an instruction encoding that does not resolve to a code section.
pub fn genuine_except_data_set(obj: &ObjInfo) -> std::collections::BTreeSet<String> {
    let mut set = std::collections::BTreeSet::new();
    for (_idx, sym) in obj.symbols.iter() {
        let Some(suffix) = sym.name.strip_prefix("except_data_") else { continue };
        if except_data_is_genuine(obj, sym) {
            set.insert(suffix.to_string());
        }
    }
    set
}

/// THE evidence test for "is this `except_data_*` symbol a real PDATA_EH
/// struct?", factored out so every consumer asks the same question. A genuine
/// struct's word1 is the C++ frame handler VA and therefore resolves to a code
/// section; a spurious one's word1 is an instruction encoding (or zero) that
/// does not.
///
/// Must be evaluated against the FULL (un-split) module — the retail XEX shares
/// one `__CxxFrameHandler` living in a different unit than most EH structs, so a
/// per-split-object lookup would reject every cross-unit handler.
///
/// Deliberately keyed on the symbol's ADDRESS, never on its name: on RB3 TU5,
/// 8,862 of 9,348 `except_data_*` symbols carry a NAME whose hex suffix does not
/// equal `address + 8` (stale text preserved across the TU0 -> TU5 rebase), so
/// any name-derived test here would be reading a fossil.
pub fn except_data_is_genuine(obj: &ObjInfo, sym: &ObjSymbol) -> bool {
    let Some(section_idx) = sym.section else { return false };
    let Some(sect) = obj.sections.get(section_idx) else { return false };
    let offset = (sym.address - sect.address) as usize;
    let handler_va = if offset + 4 <= sect.data.len() {
        u32::from_be_bytes(sect.data[offset..offset + 4].try_into().unwrap())
    } else {
        0
    };
    handler_va != 0
        && obj
            .sections
            .at_address(handler_va)
            .map(|(_, s)| s.kind == ObjSectionKind::Code)
            .unwrap_or(false)
}

/// Strip `except_data_*` Object symbols that sit on LIVE CODE, and re-grow any
/// function extent one of them truncated.
///
/// `write_coff` has skipped these since `b1bc97c` ("treating bytes as code"),
/// but that decision was made too late to matter anywhere else: the symbol had
/// already terminated the preceding function's extent and had already reached
/// `write_asm`, which emits it as an `.obj` block of `.4byte` directives. So
/// the human-readable `.s` — the artifact people and agents actually read to
/// write matching source — showed real instructions as opaque data words, and
/// the truncated function's tail was missing from its own body. This pass moves
/// that one decision UPSTREAM of the extent/symbol/asm paths, so there is ONE
/// classifier (`except_data_is_genuine`) rather than two.
///
/// Must run AFTER `apply_symbols_file` (the offenders come from the symbols
/// file) and BEFORE any CFA/extent analysis or symbol/split writing.
///
/// MEASURED on RB3 retail TU5 (45410914), against the committed symbols.txt:
/// 9,348 `except_data_*` in `.text`, 9,142 genuine and 206 spurious. Every one
/// of the 9,142 genuine blobs sits exactly at a `.pdata` `func_type == 3`
/// record's `start - 8`, and NONE of the 206 spurious ones does — i.e. on this
/// target the offenders are 100% STALE SYMBOLS-FILE FOSSILS carried across the
/// TU0 -> TU5 rebase, not live `.pdata` mis-decodes. (`b1bc97c`'s premise, that
/// LTCG `.pdata` emits `func_type == 3` records pointing into the middle of real
/// functions, does not hold on TU5 — its `.pdata` is clean.) Because nothing
/// regenerates them, stripping is a PERMANENT heal and the split's fixed point
/// is reached in one pass.
///
/// Of the 206: 121 sit strictly inside a function body, 64 sit exactly at a
/// PDATA-less function's declared end (truncating it; 552 bytes of real code
/// emitted as `.4byte`), 18 sit in unclaimed gaps, and 3 sit at the end of a
/// correctly-sized `.pdata`-anchored function.
///
/// Re-growth rules, both deliberately conservative:
///   * `.pdata`-anchored functions are NEVER extended — `.pdata` is the
///     authoritative boundary source on Xbox 360, and all 3 such cases already
///     have `declared size == .pdata size`, so growing them would corrupt a
///     correct extent.
///   * A function grows only up to the next SURVIVING symbol. The spurious
///     blob's own declared size is untrustworthy (it is fossil data): e.g.
///     `except_data_8278A2E0` @ 0x827AF280 claims 0x18, which would run through
///     the GENUINE EH struct at 0x827AF290 that belongs to the next function.
///     Stopping at the next survivor yields the correct 0x30 extent instead.
///
/// Returns (stripped, extended).
pub fn strip_spurious_except_data(obj: &mut ObjInfo) -> (usize, usize) {
    // (1) Classify. Address-keyed, never name-keyed (see `except_data_is_genuine`).
    let mut spurious: Vec<(ObjSymbolIndex, ObjSectionIndex, u64, u64)> = Vec::new();
    for (idx, sym) in obj.symbols.iter() {
        if !sym.name.starts_with("except_data_") {
            continue;
        }
        let Some(sec) = sym.section else { continue };
        // Only code sections: an `except_data_*` in .rdata/.data is not the
        // failure mode this pass exists for, and stripping it could lose a real
        // data label.
        if !matches!(obj.sections.get(sec), Some(s) if s.kind == ObjSectionKind::Code) {
            continue;
        }
        if except_data_is_genuine(obj, sym) {
            continue;
        }
        spurious.push((idx, sec, sym.address, sym.size));
    }
    if spurious.is_empty() {
        return (0, 0);
    }
    let doomed: std::collections::BTreeSet<ObjSymbolIndex> =
        spurious.iter().map(|&(idx, ..)| idx).collect();

    // (2) Surviving symbol addresses per section — the ceiling for any re-growth.
    let mut survivors: BTreeMap<ObjSectionIndex, Vec<u64>> = BTreeMap::new();
    for (idx, sym) in obj.symbols.iter() {
        if doomed.contains(&idx) || sym.flags.is_stripped() {
            continue;
        }
        if let Some(sec) = sym.section {
            survivors.entry(sec).or_default().push(sym.address);
        }
    }
    for v in survivors.values_mut() {
        v.sort_unstable();
        v.dedup();
    }

    // (3) Functions per section, for finding the one a blob truncated.
    let pdata_anchored: std::collections::BTreeSet<(ObjSectionIndex, u64)> =
        obj.pdata_funcs.iter().map(|sa| (sa.section, sa.address as u64)).collect();
    let mut funcs: BTreeMap<ObjSectionIndex, Vec<(ObjSymbolIndex, u64, u64)>> = BTreeMap::new();
    for (idx, sym) in obj.symbols.iter() {
        if doomed.contains(&idx) || sym.kind != ObjSymbolKind::Function || sym.size == 0 {
            continue;
        }
        if let Some(sec) = sym.section {
            funcs.entry(sec).or_default().push((idx, sym.address, sym.size));
        }
    }
    for v in funcs.values_mut() {
        v.sort_by_key(|&(_, a, _)| a);
    }

    // (4) Plan re-growth under an immutable borrow, then apply.
    let mut grow: Vec<(ObjSymbolIndex, u64, u64, u64)> = Vec::new(); // idx, addr, old, new
    for &(_, sec, addr, bsize) in &spurious {
        let Some(list) = funcs.get(&sec) else { continue };
        let i = match list.binary_search_by_key(&addr, |&(_, a, _)| a) {
            Ok(i) => i,
            Err(0) => continue,
            Err(i) => i - 1,
        };
        let (fidx, faddr, fsize) = list[i];
        // Only the AT_END case: the blob is exactly what stopped the function.
        // A blob strictly INSIDE a body did not truncate anything (the body
        // already covers it) — stripping alone is the whole fix there.
        if faddr + fsize != addr {
            continue;
        }
        if pdata_anchored.contains(&(sec, faddr)) {
            continue; // .pdata is authoritative; never override a correct extent
        }
        let Some(surv) = survivors.get(&sec) else { continue };
        let ceiling = match surv.partition_point(|&a| a <= addr) {
            p if p < surv.len() => surv[p],
            // No surviving symbol after it: fall back to the blob's own claimed
            // extent rather than guessing at the section end.
            _ => addr + bsize.max(4),
        };
        let new_size = ceiling - faddr;
        if new_size > fsize {
            grow.push((fidx, faddr, fsize, new_size));
        }
    }

    for &(idx, addr, old, new) in &grow {
        let existing = obj.symbols[idx].clone();
        log::info!(
            "Re-growing {} @ {:#010x}: size {:#x} -> {:#x} (was truncated by a \
             spurious except_data blob sitting on live code)",
            existing.name,
            addr,
            old,
            new,
        );
        let grown = ObjSymbol { size: new, size_known: true, ..existing };
        if let Err(e) = obj.symbols.replace(idx, grown) {
            log::warn!("Failed to re-grow truncated function #{idx}: {e:#}");
        }
    }

    // (5) Strip the offenders. Mirrors `prune_overlapping_phantom_functions`:
    // symbol indexes are referenced by relocations, so retire in place rather
    // than removing.
    for &(idx, _, addr, size) in &spurious {
        let existing = obj.symbols[idx].clone();
        log::info!(
            "Stripping spurious except_data symbol {} @ {:#010x} (size {:#x}): \
             word1 is not a code-section handler VA, so these bytes are code",
            existing.name,
            addr,
            size,
        );
        let stripped = ObjSymbol {
            name: format!("__DELETED_{}", existing.name),
            kind: ObjSymbolKind::Unknown,
            size: 0,
            flags: ObjSymbolFlagSet(
                ObjSymbolFlags::RelocationIgnore
                    | ObjSymbolFlags::NoWrite
                    | ObjSymbolFlags::NoExport
                    | ObjSymbolFlags::Stripped,
            ),
            ..existing
        };
        if let Err(e) = obj.symbols.replace(idx, stripped) {
            log::warn!("Failed to strip spurious except_data symbol #{idx}: {e:#}");
        }
    }
    log::info!(
        "Stripped {} spurious except_data symbol(s) on live code; re-grew {} truncated function(s)",
        spurious.len(),
        grow.len(),
    );
    (spurious.len(), grow.len())
}

pub fn write_coff(
    obj: &ObjInfo,
    genuine_except_data: &std::collections::BTreeSet<String>,
) -> Result<Vec<u8>> {
    // for each obj:
    let mut cur_coff =
        object::write::Object::new(BinaryFormat::Coff, Architecture::PowerPc, Endianness::Big);
    // Add a dummy symbol for PAIR relocations. MSVC writes SymbolTableIndex=0 in
    // IMAGE_REL_PPC_PAIR entries (the field encodes a displacement, not a symbol ref).
    // The `object::write` crate requires a SymbolId, so we add this early placeholder.
    let pair_dummy_sym = cur_coff.add_symbol(object::write::Symbol {
        name: b"@comp.id".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Compilation,
        weak: false,
        section: object::write::SymbolSection::Absolute,
        flags: SymbolFlags::None,
    });
    let mut sect_map: BTreeMap<SectionIndex, SectionId> = Default::default();
    let mut sym_map: BTreeMap<SymbolIndex, SymbolId> = Default::default();

    // Build sorted symbol address lists per section for inferring zero-size symbol bounds.
    let mut section_sym_addrs: BTreeMap<ObjSectionIndex, Vec<u64>> = BTreeMap::new();
    for (_, sym) in obj.symbols.iter() {
        if let Some(section_idx) = sym.section {
            section_sym_addrs.entry(section_idx).or_default().push(sym.address);
        }
    }
    for addrs in section_sym_addrs.values_mut() {
        addrs.sort();
        addrs.dedup();
    }

    // === Build EH and .pdata lookup tables ===

    // 1a. Collect except_data and except_record symbol info.
    // Key = hex suffix (function VA), value = (sym_idx, section_idx, offset_in_section, has_handler_data)
    let mut except_data_info: BTreeMap<String, (SymbolIndex, SectionIndex, u64, bool)> =
        BTreeMap::new();
    let mut except_record_sym_idxs: BTreeMap<String, SymbolIndex> = BTreeMap::new();

    for (idx, sym) in obj.symbols.iter() {
        if let Some(suffix) = sym.name.strip_prefix("except_data_") {
            if let Some(section_idx) = sym.section {
                if let Some(sect) = obj.sections.get(section_idx) {
                    let offset = sym.address - sect.address;
                    // Only treat this `except_data_<addr>` as a genuine PDATA_EH
                    // struct if its function VA is in `genuine_except_data` (built
                    // by the caller against the *full* module — word1 must resolve
                    // to a code-section handler there). See `write_coff`'s doc and
                    // `genuine_except_data_set`.
                    //
                    // RB3's LTCG-combined .pdata produced stray func_type==3
                    // records pointing *into* the middle of real functions, so a
                    // prior split run left over-broad `except_data_<addr>` symbols
                    // sitting on top of live instructions (word1 is an instruction
                    // encoding, not a handler VA). Treating those as EH structs
                    // zeroes 8 bytes of code and bolts ADDR32 handler relocs onto
                    // instructions, corrupting the COFF so objdiff renders the
                    // bytes as <illegal> and can't score otherwise byte-identical
                    // functions. Skip them here (the bytes stay code).
                    if !genuine_except_data.contains(suffix) {
                        log::debug!(
                            "Skipping spurious except_data {} @ {:#010X} (treating bytes as code)",
                            sym.name,
                            sym.address as u32,
                        );
                        continue;
                    }
                    // Read original data to check if pHandlerData is non-null
                    let hd_off = offset as usize + 4;
                    let has_handler_data = if hd_off + 4 <= sect.data.len() {
                        u32::from_be_bytes(
                            sect.data[hd_off..hd_off + 4].try_into().unwrap(),
                        ) != 0
                    } else {
                        false
                    };
                    except_data_info
                        .insert(suffix.to_string(), (idx, section_idx, offset, has_handler_data));
                }
            }
        } else if let Some(suffix) = sym.name.strip_prefix("except_record_") {
            except_record_sym_idxs.insert(suffix.to_string(), idx);
        }
    }

    // 1b. Parse original .pdata to get prolog_len and func_len per function.
    // Maps target function symbol index -> (prolog_len, func_len_in_instructions)
    let mut pdata_info: BTreeMap<SymbolIndex, (u8, u32)> = BTreeMap::new();
    let pdata_section_idx: Option<SectionIndex> =
        if let Some((idx, pdata_sec)) = obj.sections.by_name(".pdata")? {
            for (i, chunk) in pdata_sec.data.chunks_exact(8).enumerate() {
                let entry_offset = (i * 8) as u32;
                if let Some(reloc) = pdata_sec.relocations.at(entry_offset) {
                    if reloc.kind == ObjRelocKind::Absolute {
                        let word = u32::from_be_bytes(chunk[4..8].try_into()?);
                        let prolog_len = (word & 0xFF) as u8;
                        let func_len = (word >> 8) & 0x3FFFFF;
                        pdata_info.insert(reloc.target_symbol, (prolog_len, func_len));
                    }
                }
            }
            Some(idx)
        } else {
            None
        };

    // 1c. Collect functions for .pdata reconstruction.
    // Each entry: (func_sym_idx, func_offset_in_section, prolog_len, func_len, exception_flag)
    let mut pdata_entries: Vec<(SymbolIndex, u64, u8, u32, bool)> = Vec::new();

    if pdata_section_idx.is_some() {
        for (sym_idx, sym) in obj.symbols.iter() {
            if sym.kind != ObjSymbolKind::Function {
                continue;
            }
            let Some(section_idx) = sym.section else { continue };
            let Some(sect) = obj.sections.get(section_idx) else { continue };
            if sect.kind != ObjSectionKind::Code || sect.name != ".text" {
                continue;
            }
            // Filter out EH thunks, metadata symbols, and COMDAT functions.
            // COMDAT functions move to .text$dup sections in the COFF output, which
            // resolve to different VAs than .text, breaking .pdata sorted order.
            if sym.name.starts_with("__unwind$")
                || sym.name.starts_with("except_data_")
                || sym.name.starts_with("except_record_")
                || sym.name.starts_with("lbl_")
                || obj.comdat_symbols.contains(&sym.name)
            {
                continue;
            }

            let func_offset = sym.address - sect.address;
            let addr_hex = format!("{:08X}", sym.address as u32);
            let exception_flag = except_data_info.contains_key(&addr_hex);

            let (prolog_len, func_len) = if let Some(&(pl, fl)) = pdata_info.get(&sym_idx) {
                (pl, fl)
            } else if sym.size > 0 {
                (0u8, (sym.size / 4) as u32)
            } else if let Some(addrs) = section_sym_addrs.get(&section_idx) {
                // Infer size from distance to next symbol
                let pos = addrs.partition_point(|&a| a <= sym.address);
                let next_addr = if pos < addrs.len() {
                    addrs[pos]
                } else {
                    sect.address + sect.size
                };
                let inferred = next_addr - sym.address;
                if inferred > 0 {
                    (0u8, (inferred / 4) as u32)
                } else {
                    continue;
                }
            } else {
                continue;
            };

            pdata_entries.push((sym_idx, func_offset, prolog_len, func_len, exception_flag));
        }

        // Sort by function offset (ascending) — required by LNK1223
        pdata_entries.sort_by_key(|e| e.1);
    }

    // 1d. Generate .pdata section data
    let mut generated_pdata = vec![0u8; pdata_entries.len() * 8];
    for (i, &(_, _, prolog_len, func_len, exception_flag)) in pdata_entries.iter().enumerate() {
        let base = i * 8;
        // Word 0: placeholder 0 (ADDR32 reloc will fill BeginAddress)
        // Word 1: PrologLen[7:0] | FuncLen[29:8] | ThirtyTwoBit[30] | ExceptionFlag[31]
        let word1: u32 = (prolog_len as u32)
            | ((func_len & 0x3FFFFF) << 8)
            | (1 << 30)
            | ((exception_flag as u32) << 31);
        generated_pdata[base + 4..base + 8].copy_from_slice(&word1.to_be_bytes());
    }

    // Collect COMDAT regions: both __unwind$ symbols and globally-duplicated symbols.
    // Maps (section_index, offset_in_section) -> (symbol_index, size)
    let mut comdat_regions: BTreeMap<(ObjSectionIndex, u64), (ObjSymbolIndex, u64)> =
        Default::default();
    for (idx, sym) in obj.symbols.iter() {
        let is_comdat = sym.name.starts_with("__unwind$")
            || obj.comdat_symbols.contains(&sym.name);
        if !is_comdat || sym.section.is_none() {
            continue;
        }
        let section_idx = sym.section.unwrap();
        let Some(sect) = obj.sections.get(section_idx) else { continue };
        if sect.kind == ObjSectionKind::Bss {
            continue;
        }
        let offset = sym.address - sect.address;

        // Use known size, or infer for zero-size symbols
        let effective_size = if sym.size > 0 {
            sym.size
        } else if sym.name.starts_with("__real@") {
            // Float/double constants: size from hex digit count
            match sym.name.len() - 7 {
                8 => 4,   // float: __real@XXXXXXXX
                16 => 8,  // double: __real@XXXXXXXXXXXXXXXX
                _ => continue,
            }
        } else {
            // Infer size as distance to next symbol in same section
            let addrs = match section_sym_addrs.get(&section_idx) {
                Some(a) => a,
                None => continue,
            };
            let pos = addrs.partition_point(|&a| a <= sym.address);
            let next_addr = if pos < addrs.len() {
                addrs[pos]
            } else {
                sect.address + sect.size
            };
            let inferred = next_addr - sym.address;
            if inferred == 0 {
                continue;
            }
            inferred
        };

        comdat_regions.insert((section_idx, offset), (idx, effective_size));
    }

    // Remove COMDAT entries involved in REL14 relocations.
    // REL14 (conditional branch) has only ±32KB range. If either the source or
    // target of a REL14 is in a separate .text$dup COMDAT section, the linker may
    // interleave other sections between them, causing REL14 fixup overflow (LNK2013).
    // Keeping both source and target in the contiguous main .text prevents overflow.
    {
        let mut rel14_keep: Vec<(ObjSectionIndex, u64)> = Vec::new();
        for (sect_idx, sect) in obj.sections.iter() {
            for (addr, reloc) in sect.relocations.iter() {
                if matches!(reloc.kind, ObjRelocKind::PpcRel14) {
                    // Keep the TARGET in main .text
                    let target_sym = &obj.symbols[reloc.target_symbol];
                    if let Some(target_section) = target_sym.section {
                        let target_sect = &obj.sections[target_section];
                        let offset = target_sym.address - target_sect.address;
                        rel14_keep.push((target_section, offset));
                    }
                    // Keep the SOURCE (containing function) in main .text
                    // Find which COMDAT region contains this relocation address
                    let reloc_offset = addr as u64;
                    for (&(si, start), &(_sym_idx, sz)) in &comdat_regions {
                        if si == sect_idx && reloc_offset >= start && reloc_offset < start + sz {
                            rel14_keep.push((si, start));
                            break;
                        }
                    }
                }
            }
        }
        for key in &rel14_keep {
            if comdat_regions.remove(key).is_some() {
                log::debug!("Keeping REL14-involved function in main .text (not COMDAT): {:?}", key);
            }
        }
    }

    // Track COMDAT sections: maps (section_index, offset) -> comdat_section_id
    let mut comdat_extracted_sections: BTreeMap<(ObjSectionIndex, u64), SectionId> = Default::default();

    // insert the sections
    let mut generated_pdata_section_id: Option<SectionId> = None;
    for (idx, sect) in obj.sections.iter() {
        // Handle .pdata reconstruction: use generated data instead of original
        if Some(idx) == pdata_section_idx {
            let sect_kind = match sect.kind {
                ObjSectionKind::Code => SectionKind::Text,
                ObjSectionKind::Data => SectionKind::Data,
                ObjSectionKind::ReadOnlyData => SectionKind::ReadOnlyData,
                ObjSectionKind::Bss => SectionKind::UninitializedData,
            };
            let sect_id =
                cur_coff.add_section(Vec::new(), sect.name.clone().into_bytes(), sect_kind);
            if !generated_pdata.is_empty() {
                cur_coff.append_section_data(sect_id, &generated_pdata, sect.align);
            }
            generated_pdata_section_id = Some(sect_id);
            sect_map.insert(idx, sect_id);

            // Add a section symbol for .pdata — MSVC linker requires this for validation
            cur_coff.add_symbol(object::write::Symbol {
                name: b".pdata".to_vec(),
                value: 0,
                size: 0,
                kind: object::SymbolKind::Section,
                scope: object::SymbolScope::Compilation,
                weak: false,
                section: object::write::SymbolSection::Section(sect_id),
                flags: object::SymbolFlags::None,
            });

            continue;
        }

        // Fix relocation sites: replace stale XEX values with correct addends.
        // COFF relocations are additive — the linker reads the existing value at each
        // relocation site and uses it as an addend. If we leave the original XEX values
        // (absolute VAs, branch displacements, address immediates) in place, they become
        // spurious addends that corrupt the linked output.
        let mut data = sect.data.clone();
        if sect.kind != ObjSectionKind::Bss {
            for (addr, reloc) in sect.relocations.iter() {
                let offset = addr as usize;
                match reloc.kind {
                    ObjRelocKind::Absolute => {
                        // ADDR32: entire 4-byte value is the address/addend
                        if offset + 4 <= data.len() {
                            let addend = reloc.addend as i32;
                            data[offset..offset + 4]
                                .copy_from_slice(&addend.to_be_bytes());
                        }
                    }
                    ObjRelocKind::PpcRel24 => {
                        // REL24 (bl/b): displacement in bits [25:2].
                        // MSVC PPC linker convention: the linker computes
                        //   new_disp = (S + A) - section_start_VA
                        // where A is the existing instruction displacement (addend).
                        // The compiler sets A = -(offset_in_section) so that:
                        //   CPU target = instruction_VA + new_disp
                        //              = (section_start + off) + (S - off - section_start)
                        //              = S  (correct)
                        // We must replicate this convention for split objects.
                        if offset + 4 <= data.len() {
                            let insn = u32::from_be_bytes(
                                data[offset..offset + 4].try_into().unwrap(),
                            );
                            let neg_offset = (-(offset as i32)) as u32;
                            let new_insn = (insn & 0xFC000003) | (neg_offset & 0x03FFFFFC);
                            data[offset..offset + 4]
                                .copy_from_slice(&new_insn.to_be_bytes());
                        }
                    }
                    ObjRelocKind::PpcAddr16Ha | ObjRelocKind::PpcAddr16Lo => {
                        // REFHI/REFLO: 16-bit immediate in bits [15:0].
                        // COFF relocations are additive — the linker reads the
                        // existing immediate as an addend. The original XEX has
                        // resolved addresses baked in (e.g., lis r11, 0x8200),
                        // which would become spurious addends causing overflow.
                        // Zero the immediate to match compiler output (addend=0).
                        if offset + 4 <= data.len() {
                            let insn = u32::from_be_bytes(
                                data[offset..offset + 4].try_into().unwrap(),
                            );
                            let new_insn = insn & 0xFFFF0000;
                            data[offset..offset + 4]
                                .copy_from_slice(&new_insn.to_be_bytes());
                        }
                    }
                    _ => {}
                }
            }
        }

        // Zero out baked-in VAs in except_data PDATA_EH blobs (8 bytes before EH functions).
        // We'll add proper ADDR32 relocations for these later.
        if sect.name == ".text" {
            for &(_, ed_sect_idx, ed_offset, _) in except_data_info.values() {
                if ed_sect_idx == idx {
                    let start = ed_offset as usize;
                    if start + 8 <= data.len() {
                        data[start..start + 8].fill(0);
                    }
                }
            }
        }

        // Extract COMDAT regions into individual COMDAT sections
        let section_comdats: Vec<_> = comdat_regions
            .range((idx, 0)..(idx, u64::MAX))
            .map(|(&(_, offset), &(sym_idx, size))| (offset, size, sym_idx))
            .collect();

        if !section_comdats.is_empty() {
            for &(offset, size, sym_idx) in &section_comdats {
                let start = offset as usize;
                let end = start + size as usize;
                if end <= data.len() {
                    let mut comdat_data = data[start..end].to_vec();
                    // Re-fix REL24 displacements for COMDAT-relative offsets.
                    // The parent fixup (above) set displacement = -(offset_in_parent),
                    // but COMDAT sections need -(offset_in_comdat).
                    for (raddr, reloc) in sect.relocations.iter() {
                        let abs_off = raddr as usize;
                        if abs_off >= start && abs_off < end {
                            if matches!(reloc.kind, ObjRelocKind::PpcRel24) {
                                let comdat_off = abs_off - start;
                                if comdat_off + 4 <= comdat_data.len() {
                                    let insn = u32::from_be_bytes(
                                        comdat_data[comdat_off..comdat_off + 4]
                                            .try_into()
                                            .unwrap(),
                                    );
                                    let neg_offset = (-(comdat_off as i32)) as u32;
                                    let new_insn =
                                        (insn & 0xFC000003) | (neg_offset & 0x03FFFFFC);
                                    comdat_data[comdat_off..comdat_off + 4]
                                        .copy_from_slice(&new_insn.to_be_bytes());
                                }
                            }
                        }
                    }
                    // Use .text$x for __unwind$, section-appropriate $dup for others
                    let sym_name = &obj.symbols[sym_idx].name;
                    let (comdat_sect_name, comdat_sect_kind) = if sym_name.starts_with("__unwind$") {
                        (b".text$x".to_vec(), SectionKind::Text)
                    } else {
                        match sect.kind {
                            ObjSectionKind::Code => (b".text$dup".to_vec(), SectionKind::Text),
                            ObjSectionKind::ReadOnlyData => (b".rdata$dup".to_vec(), SectionKind::ReadOnlyData),
                            ObjSectionKind::Data => (b".data$dup".to_vec(), SectionKind::Data),
                            ObjSectionKind::Bss => continue,
                        }
                    };
                    let comdat_sect_id = cur_coff.add_section(
                        Vec::new(),
                        comdat_sect_name,
                        comdat_sect_kind,
                    );
                    // Ensure the section has a section symbol (required by COFF COMDAT)
                    cur_coff.section_symbol(comdat_sect_id);
                    cur_coff.append_section_data(comdat_sect_id, &comdat_data, sect.align.max(4));
                    comdat_extracted_sections.insert((idx, offset), comdat_sect_id);
                    // Zero out COMDAT bytes in parent section to prevent duplication.
                    // The authoritative copy lives in the COMDAT section; parent section
                    // bytes become dead space. Relocations from this region are also
                    // skipped in the parent (see relocation loop below).
                    data[start..end].fill(0);
                }
            }
        }

        // Rename .CRT sections to .CRT$XCU so the MSVC linker places them
        // between .CRT$XCA (start sentinel) and .CRT$XCZ (end sentinel),
        // which is required for CRT dynamic initializers to run at startup.
        let coff_sect_name = if sect.name == ".CRT" {
            b".CRT$XCU".to_vec()
        } else {
            sect.name.clone().into_bytes()
        };
        let sect_id =
            cur_coff.add_section(Vec::new(), coff_sect_name, match sect.kind {
                ObjSectionKind::Code => SectionKind::Text,
                ObjSectionKind::Data => SectionKind::Data,
                ObjSectionKind::ReadOnlyData => SectionKind::ReadOnlyData,
                ObjSectionKind::Bss => SectionKind::UninitializedData,
            });
        if sect.kind != ObjSectionKind::Bss {
            cur_coff.append_section_data(sect_id, &data, sect.align);
        } else {
            cur_coff.append_section_bss(sect_id, sect.size, sect.align);
        }
        sect_map.insert(idx, sect_id);
    }

    // insert the symbols
    let mut comdat_pending: Vec<(SectionId, SymbolId)> = Vec::new();

    for (idx, sym) in obj.symbols.iter() {
        // For COMDAT symbols (__unwind$ or duplicated globals): create a LOCAL symbol
        // in the parent section (for intra-object refs) AND a GLOBAL symbol in the
        // COMDAT section (for cross-object dedup via IMAGE_COMDAT_SELECT_ANY).
        let is_comdat_sym = (sym.name.starts_with("__unwind$")
            || obj.comdat_symbols.contains(&sym.name))
            && sym.section.is_some();
        let comdat_info = if is_comdat_sym {
            let section_idx = sym.section.unwrap();
            let offset = if let Some(sect) = obj.sections.get(section_idx) {
                sym.address - sect.address
            } else {
                0
            };
            comdat_extracted_sections.get(&(section_idx, offset)).copied()
        } else {
            None
        };

        if let Some(comdat_sect_id) = comdat_info {
            let sym_kind = match sym.kind {
                ObjSymbolKind::Function => SymbolKind::Text,
                ObjSymbolKind::Object => SymbolKind::Data,
                _ => SymbolKind::Text,
            };
            // Create EXTERNAL symbol in COMDAT section only.
            // No LOCAL copy in parent section — all references (intra and inter-object)
            // resolve through the COMDAT symbol, enabling proper SELECT_ANY dedup.
            let comdat_sym_id = cur_coff.add_symbol(object::write::Symbol {
                name: sym.name.clone().into_bytes(),
                value: 0,
                size: 0,
                kind: sym_kind,
                scope: SymbolScope::Linkage, // GLOBAL
                weak: false,
                section: object::write::SymbolSection::Section(comdat_sect_id),
                flags: SymbolFlags::None,
            });
            sym_map.insert(idx, comdat_sym_id);
            comdat_pending.push((comdat_sect_id, comdat_sym_id));
            continue;
        }

        // Skip pdata@ symbols — these are synthetic symbols created during XEX parsing.
        // Our reconstructed .pdata section uses ADDR32 relocations to function symbols
        // instead of these per-entry symbols.
        if sym.name.starts_with("pdata@") {
            continue;
        }

        let sym_id = cur_coff.add_symbol(object::write::Symbol {
            name: sym.name.clone().into_bytes(),
            value: match sym.section {
                Some(idx) => match obj.sections.get(idx) {
                    Some(sect) => sym.address - sect.address,
                    None => bail!("Could not find section for symbol {}!", sym.name),
                },
                None => 0,
            },
            size: 0,
            kind: match sym.kind {
                ObjSymbolKind::Function => SymbolKind::Text,
                ObjSymbolKind::Object => SymbolKind::Data,
                ObjSymbolKind::Section => SymbolKind::Section,
                ObjSymbolKind::Unknown => match sym.section {
                    // SymbolKind::Label forces IMAGE_SYM_CLASS_LABEL in COFF regardless
                    // of scope, so use Text for global symbols to get EXTERNAL storage class
                    Some(_) if sym.flags.0.contains(ObjSymbolFlags::Global) => SymbolKind::Text,
                    Some(_) => SymbolKind::Label,
                    None => SymbolKind::Unknown,
                },
            },
            scope: match sym.flags.scope() {
                ObjSymbolScope::Local if is_auto_label(sym) => SymbolScope::Linkage,
                ObjSymbolScope::Local => SymbolScope::Compilation,
                _ => SymbolScope::Linkage,
            },
            weak: false, // sym.flags.scope() == ObjSymbolScope::Weak,
            section: match sym.section {
                Some(idx) => {
                    object::write::SymbolSection::Section(sect_map.get(&idx).unwrap().clone())
                }
                None => object::write::SymbolSection::Undefined,
            },
            flags: SymbolFlags::None,
        });
        sym_map.insert(idx, sym_id);
    }

    // Register COMDAT groups (IMAGE_COMDAT_SELECT_ANY)
    for (comdat_sect_id, comdat_sym_id) in comdat_pending {
        cur_coff.add_comdat(object::write::Comdat {
            kind: ComdatKind::Any,
            symbol: comdat_sym_id,
            sections: vec![comdat_sect_id],
        });
    }

    // Create __CxxFrameHandler extern symbol for PDATA_EH relocations
    let cxx_handler_sym_id: Option<SymbolId> = if !except_data_info.is_empty() {
        // Check if __CxxFrameHandler already exists in the symbol table
        let existing = obj
            .symbols
            .iter()
            .find(|(_, s)| s.name == "__CxxFrameHandler")
            .and_then(|(idx, _)| sym_map.get(&idx).copied());
        Some(existing.unwrap_or_else(|| {
            cur_coff.add_symbol(object::write::Symbol {
                name: b"__CxxFrameHandler".to_vec(),
                value: 0,
                size: 0,
                kind: SymbolKind::Text,
                scope: SymbolScope::Linkage,
                weak: false,
                section: object::write::SymbolSection::Undefined,
                flags: SymbolFlags::None,
            })
        }))
    } else {
        None
    };

    // insert the relocs
    for (sect_idx, sect) in obj.sections.iter() {
        // Skip original .pdata relocations — we've reconstructed the section
        if Some(sect_idx) == pdata_section_idx {
            continue;
        }
        for (addr, reloc) in sect.relocations.iter() {
            let sym_id = match sym_map.get(&reloc.target_symbol) {
                Some(id) => id,
                None => {
                    // Skip relocations targeting pdata@ symbols we omitted
                    if let Some((_, sym)) = obj.symbols.iter()
                        .find(|(i, _)| *i == reloc.target_symbol)
                    {
                        if sym.name.starts_with("pdata@") {
                            continue;
                        }
                        bail!("Could not find symbol ID for index {} (name: '{}', section: {:?})",
                            reloc.target_symbol, sym.name, sym.section)
                    }
                    bail!("Could not find symbol ID for index {} (no such symbol)",
                        reloc.target_symbol)
                }
            };

            // Check if this relocation originates from within a COMDAT region;
            // if so, also add it to the COMDAT section (with adjusted offset).
            let offset = addr as u64;
            if let Some(&(_, _size)) = comdat_regions.get(&(sect_idx, 0)).or_else(|| {
                // Find the region that contains this offset
                comdat_regions
                    .range(..=(sect_idx, offset))
                    .rev()
                    .next()
                    .filter(|(&(si, start), &(_, sz))| {
                        si == sect_idx && offset >= start && offset < start + sz
                    })
                    .map(|(_, v)| v)
            }) {
                // Find which COMDAT region contains this offset
                for (&(si, start), &(_sym_idx, sz)) in &comdat_regions {
                    if si == sect_idx && offset >= start && offset < start + sz {
                        if let Some(&comdat_sect_id) =
                            comdat_extracted_sections.get(&(sect_idx, start))
                        {
                            let comdat_offset = offset - start;
                            cur_coff.add_relocation(
                                comdat_sect_id,
                                object::write::Relocation {
                                    offset: comdat_offset,
                                    symbol: sym_id.clone(),
                                    addend: 0,
                                    flags: RelocationFlags::Coff { typ: reloc.to_coff() },
                                },
                            )?;
                            match reloc.kind {
                                ObjRelocKind::PpcAddr16Ha | ObjRelocKind::PpcAddr16Lo => {
                                    cur_coff.add_relocation(
                                        comdat_sect_id,
                                        object::write::Relocation {
                                            offset: comdat_offset,
                                            symbol: pair_dummy_sym,
                                            addend: 0,
                                            flags: RelocationFlags::Coff {
                                                typ: object::pe::IMAGE_REL_PPC_PAIR,
                                            },
                                        },
                                    )?;
                                }
                                _ => {}
                            }
                        }
                        break;
                    }
                }
            }

            // Add to main section ONLY if not from a COMDAT region.
            // COMDAT regions are zeroed in parent section data; their relocations
            // live exclusively in the COMDAT section to avoid patching dead bytes.
            let in_comdat = comdat_regions
                .range(..=(sect_idx, addr as u64))
                .rev()
                .next()
                .map_or(false, |(&(si, start), &(_, sz))| {
                    si == sect_idx && (addr as u64) >= start && (addr as u64) < start + sz
                });
            if !in_comdat {
                cur_coff.add_relocation(
                    sect_map.get(&sect_idx).unwrap().clone(),
                    object::write::Relocation {
                        offset: addr as u64,
                        symbol: sym_id.clone(),
                        addend: 0,
                        flags: RelocationFlags::Coff { typ: reloc.to_coff() },
                    },
                )?;
                // MSVC requires an extra PAIR relocation to accompany REFHI/REFLO.
                // The PAIR's SymbolTableIndex field encodes a 16-bit displacement (not
                // an actual symbol reference). MSVC writes 0 here; we use pair_dummy_sym
                // (symbol index 0) to match.
                match reloc.kind {
                    ObjRelocKind::PpcAddr16Ha | ObjRelocKind::PpcAddr16Lo => {
                        cur_coff.add_relocation(
                            sect_map.get(&sect_idx).unwrap().clone(),
                            object::write::Relocation {
                                offset: addr as u64,
                                symbol: pair_dummy_sym,
                                addend: 0,
                                flags: RelocationFlags::Coff { typ: object::pe::IMAGE_REL_PPC_PAIR },
                            },
                        )?;
                    }
                    _ => {}
                }
            }
        }
    }

    // Add generated .pdata ADDR32 relocations (one per entry, targeting function symbol)
    if let Some(pdata_sect_id) = generated_pdata_section_id {
        for (i, &(func_sym_idx, _, _, _, _)) in pdata_entries.iter().enumerate() {
            if let Some(&func_sym_id) = sym_map.get(&func_sym_idx) {
                cur_coff.add_relocation(
                    pdata_sect_id,
                    object::write::Relocation {
                        offset: (i * 8) as u64,
                        symbol: func_sym_id,
                        addend: 0,
                        flags: RelocationFlags::Coff {
                            typ: object::pe::IMAGE_REL_PPC_ADDR32,
                        },
                    },
                )?;
            }
        }
    }

    // Add ADDR32 relocations for except_data PDATA_EH blobs in .text
    if let Some(handler_sym_id) = cxx_handler_sym_id {
        for (suffix, &(_, ed_sect_idx, ed_offset, has_handler_data)) in &except_data_info {
            if let Some(&text_sect_id) = sect_map.get(&ed_sect_idx) {
                // ADDR32 at offset+0 → __CxxFrameHandler
                cur_coff.add_relocation(
                    text_sect_id,
                    object::write::Relocation {
                        offset: ed_offset,
                        symbol: handler_sym_id,
                        addend: 0,
                        flags: RelocationFlags::Coff {
                            typ: object::pe::IMAGE_REL_PPC_ADDR32,
                        },
                    },
                )?;

                // ADDR32 at offset+4 → except_record_* (if pHandlerData was non-null)
                if has_handler_data {
                    if let Some(&record_sym_idx) = except_record_sym_idxs.get(suffix) {
                        if let Some(&record_sym_id) = sym_map.get(&record_sym_idx) {
                            cur_coff.add_relocation(
                                text_sect_id,
                                object::write::Relocation {
                                    offset: ed_offset + 4,
                                    symbol: record_sym_id,
                                    addend: 0,
                                    flags: RelocationFlags::Coff {
                                        typ: object::pe::IMAGE_REL_PPC_ADDR32,
                                    },
                                },
                            )?;
                        }
                    }
                }
            }
        }
    }

    // finally, write the COFF
    let coff_data = cur_coff.write()?;
    Ok(coff_data)
}

pub fn coff_path_for_unit(unit: &str) -> Utf8NativePathBuf {
    Utf8UnixPath::new(unit).with_encoding().with_extension("obj")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjRelocations, ObjSection, ObjSectionKind, ObjSymbol,
        ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
    };

    /// Build a minimal relocatable ObjInfo with one .text section and one symbol.
    fn make_relocatable_obj(sym_kind: ObjSymbolKind, sym_flags: ObjSymbolFlagSet) -> ObjInfo {
        let section = ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: 0,
            size: 4,
            data: vec![0x60, 0x00, 0x00, 0x00], // nop
            align: 4,
            elf_index: 0,
            relocations: ObjRelocations::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: Default::default(),
        };
        let symbol = ObjSymbol {
            name: "test_sym".into(),
            address: 0,
            section: Some(0),
            size: 4,
            size_known: true,
            flags: sym_flags,
            kind: sym_kind,
            ..Default::default()
        };
        let mut obj = ObjInfo::new(
            ObjKind::Relocatable,
            ObjArchitecture::PowerPc,
            "test.obj".into(),
            vec![],
            vec![section],
        );
        obj.symbols.add_direct(symbol).unwrap();
        obj
    }

    /// Parse COFF symbol table entries, returning (name, storage_class) pairs.
    fn parse_coff_symbol_classes(coff_data: &[u8]) -> Vec<(String, u8)> {
        let sym_table_offset =
            u32::from_le_bytes(coff_data[8..12].try_into().unwrap()) as usize;
        let num_symbols =
            u32::from_le_bytes(coff_data[12..16].try_into().unwrap()) as usize;
        let string_table_start = sym_table_offset + num_symbols * 18;

        let mut symbols = Vec::new();
        let mut i = 0;
        while i < num_symbols {
            let off = sym_table_offset + i * 18;
            let name_bytes = &coff_data[off..off + 8];
            let name = if u32::from_le_bytes(name_bytes[0..4].try_into().unwrap()) == 0 {
                // Long name: offset into string table
                let str_off =
                    u32::from_le_bytes(name_bytes[4..8].try_into().unwrap()) as usize;
                let start = string_table_start + str_off;
                let end = coff_data[start..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| start + p)
                    .unwrap_or(coff_data.len());
                String::from_utf8_lossy(&coff_data[start..end]).to_string()
            } else {
                // Short name: inline
                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&name_bytes[..end]).to_string()
            };
            let storage_class = coff_data[off + 16];
            let num_aux = coff_data[off + 17] as usize;
            symbols.push((name, storage_class));
            i += 1 + num_aux;
        }
        symbols
    }

    const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
    const IMAGE_SYM_CLASS_LABEL: u8 = 6;

    /// Global + Unknown kind → EXTERNAL (the bug fix: previously was LABEL)
    #[test]
    fn test_write_coff_global_unknown_symbol_is_external() {
        let obj = make_relocatable_obj(
            ObjSymbolKind::Unknown,
            ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
        );
        let coff_data = write_coff(&obj, &Default::default()).unwrap();
        let symbols = parse_coff_symbol_classes(&coff_data);
        let (_, storage_class) = symbols
            .iter()
            .find(|(name, _)| name == "test_sym")
            .expect("Symbol test_sym not found in COFF output");
        assert_eq!(
            *storage_class, IMAGE_SYM_CLASS_EXTERNAL,
            "Global+Unknown should be EXTERNAL (2), got {storage_class}"
        );
    }

    /// Local + Unknown kind → LABEL (this was the original behavior, still correct)
    #[test]
    fn test_write_coff_local_unknown_symbol_is_label() {
        let obj = make_relocatable_obj(
            ObjSymbolKind::Unknown,
            ObjSymbolFlagSet(ObjSymbolFlags::Local.into()),
        );
        let coff_data = write_coff(&obj, &Default::default()).unwrap();
        let symbols = parse_coff_symbol_classes(&coff_data);
        let (_, storage_class) = symbols
            .iter()
            .find(|(name, _)| name == "test_sym")
            .expect("Symbol test_sym not found in COFF output");
        assert_eq!(
            *storage_class, IMAGE_SYM_CLASS_LABEL,
            "Local+Unknown should be LABEL (6), got {storage_class}"
        );
    }

    /// __unwind$ symbols produce a single EXTERNAL COMDAT symbol in .text$x
    #[test]
    fn test_write_coff_unwind_symbol_is_comdat() {
        let section = ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: 0,
            size: 40,
            data: vec![0x60; 40], // 10 nops (40 bytes)
            align: 4,
            elf_index: 0,
            relocations: ObjRelocations::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: Default::default(),
        };
        let unwind_sym = ObjSymbol {
            name: "__unwind$12345".into(),
            address: 0,
            section: Some(0),
            size: 40,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            kind: ObjSymbolKind::Function,
            ..Default::default()
        };
        let mut obj = ObjInfo::new(
            ObjKind::Relocatable,
            ObjArchitecture::PowerPc,
            "test.obj".into(),
            vec![],
            vec![section],
        );
        obj.symbols.add_direct(unwind_sym).unwrap();
        let coff_data = write_coff(&obj, &Default::default()).unwrap();

        // Parse COFF and verify a single EXTERNAL __unwind$ symbol in COMDAT .text$x
        let symbols = parse_coff_symbol_classes(&coff_data);
        let unwind_syms: Vec<_> = symbols
            .iter()
            .filter(|(name, _)| name == "__unwind$12345")
            .collect();
        assert_eq!(
            unwind_syms.len(),
            1,
            "Expected 1 __unwind$ symbol (EXTERNAL in COMDAT), got {}",
            unwind_syms.len()
        );
        assert!(
            unwind_syms.iter().any(|(_, c)| *c == IMAGE_SYM_CLASS_EXTERNAL),
            "Expected a GLOBAL (EXTERNAL=2) __unwind$ symbol in COMDAT .text$x"
        );

        // Verify there's a .text$x section with COMDAT flag
        let num_sections = u16::from_le_bytes(coff_data[2..4].try_into().unwrap()) as usize;
        let mut found_comdat = false;
        for i in 0..num_sections {
            let off = 20 + i * 40;
            let name = String::from_utf8_lossy(&coff_data[off..off + 8])
                .trim_end_matches('\0')
                .to_string();
            if name == ".text$x" {
                found_comdat = true;
                let chars =
                    u32::from_le_bytes(coff_data[off + 36..off + 40].try_into().unwrap());
                assert!(
                    chars & 0x1000 != 0,
                    ".text$x should have IMAGE_SCN_LNK_COMDAT flag, got 0x{chars:08X}"
                );
            }
        }
        assert!(found_comdat, "Expected a .text$x COMDAT section for __unwind$");
    }

    /// Global + Function kind → EXTERNAL
    #[test]
    fn test_write_coff_function_symbol_is_external() {
        let obj = make_relocatable_obj(
            ObjSymbolKind::Function,
            ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
        );
        let coff_data = write_coff(&obj, &Default::default()).unwrap();
        let symbols = parse_coff_symbol_classes(&coff_data);
        let (_, storage_class) = symbols
            .iter()
            .find(|(name, _)| name == "test_sym")
            .expect("Symbol test_sym not found in COFF output");
        assert_eq!(
            *storage_class, IMAGE_SYM_CLASS_EXTERNAL,
            "Global+Function should be EXTERNAL (2), got {storage_class}"
        );
    }

    /// Parse COFF section headers, returning (name, raw_data_offset, raw_data_size) tuples.
    fn parse_coff_sections(coff_data: &[u8]) -> Vec<(String, usize, usize)> {
        let num_sections = u16::from_le_bytes(coff_data[2..4].try_into().unwrap()) as usize;
        let mut sections = Vec::new();
        for i in 0..num_sections {
            let off = 20 + i * 40;
            let name = String::from_utf8_lossy(&coff_data[off..off + 8])
                .trim_end_matches('\0')
                .to_string();
            let raw_data_size =
                u32::from_le_bytes(coff_data[off + 16..off + 20].try_into().unwrap()) as usize;
            let raw_data_offset =
                u32::from_le_bytes(coff_data[off + 20..off + 24].try_into().unwrap()) as usize;
            sections.push((name, raw_data_offset, raw_data_size));
        }
        sections
    }

    /// COMDAT-marked function bytes are zeroed in parent .text section
    /// and preserved only in the COMDAT .text$dup section (no duplication).
    #[test]
    fn test_comdat_bytes_not_duplicated_in_parent_section() {
        // Create a .text section with two functions:
        // - func_a at offset 0 (8 bytes, normal)
        // - func_b at offset 8 (8 bytes, COMDAT)
        let func_a_bytes = [0x7C, 0x08, 0x02, 0xA6, 0x4E, 0x80, 0x00, 0x20]; // mflr r0; blr
        let func_b_bytes = [0x38, 0x60, 0x00, 0x01, 0x4E, 0x80, 0x00, 0x20]; // li r3,1; blr
        let mut text_data = Vec::new();
        text_data.extend_from_slice(&func_a_bytes);
        text_data.extend_from_slice(&func_b_bytes);

        let section = ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: 0,
            size: 16,
            data: text_data,
            align: 4,
            elf_index: 0,
            relocations: ObjRelocations::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: Default::default(),
        };

        let sym_a = ObjSymbol {
            name: "func_a".into(),
            address: 0,
            section: Some(0),
            size: 8,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            kind: ObjSymbolKind::Function,
            ..Default::default()
        };
        let sym_b = ObjSymbol {
            name: "func_b".into(),
            address: 8,
            section: Some(0),
            size: 8,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            kind: ObjSymbolKind::Function,
            ..Default::default()
        };

        let mut obj = ObjInfo::new(
            ObjKind::Relocatable,
            ObjArchitecture::PowerPc,
            "test.obj".into(),
            vec![],
            vec![section],
        );
        obj.symbols.add_direct(sym_a).unwrap();
        obj.symbols.add_direct(sym_b).unwrap();
        // Mark func_b as COMDAT
        obj.comdat_symbols.insert("func_b".into());

        let coff_data = write_coff(&obj, &Default::default()).unwrap();

        // Parse sections
        let sections = parse_coff_sections(&coff_data);

        // Find .text section — should have func_b's bytes zeroed
        let (_, text_offset, text_size) = sections
            .iter()
            .find(|(name, _, _)| name == ".text")
            .expect(".text section not found");
        assert_eq!(*text_size, 16, ".text should still be 16 bytes");
        let text_bytes = &coff_data[*text_offset..*text_offset + *text_size];
        // func_a bytes (offset 0..8) should be preserved
        assert_eq!(
            &text_bytes[0..8], &func_a_bytes,
            "func_a bytes should be preserved in .text"
        );
        // func_b bytes (offset 8..16) should be zeroed (extracted to COMDAT)
        assert_eq!(
            &text_bytes[8..16], &[0u8; 8],
            "func_b bytes should be zeroed in parent .text (moved to COMDAT)"
        );

        // Find COMDAT payload section (name may be truncated/indirected in COFF),
        // then verify it contains func_b bytes.
        let (_, dup_offset, dup_size) = sections
            .iter()
            .find(|(name, off, size)| {
                let section_bytes = &coff_data[*off..*off + *size];
                (name.starts_with(".text$") || name.starts_with('/'))
                    && *size == 8
                    && section_bytes == func_b_bytes
            })
            .expect("COMDAT payload section for func_b not found");
        assert_eq!(*dup_size, 8, "COMDAT payload section should be 8 bytes (func_b only)");
        let dup_bytes = &coff_data[*dup_offset..*dup_offset + *dup_size];
        assert_eq!(
            dup_bytes, &func_b_bytes,
            "func_b bytes should be in the COMDAT payload section"
        );
    }

    /// LZX decompression: test that try_get_exe handles the Compressed path.
    /// We construct a minimal XEX-style LZX block and verify round-trip.
    #[test]
    fn test_lzx_decompression_round_trip() {
        use lzxd::{Lzxd, WindowSize};

        // Step 1: Create uncompressed data (must be <= window size = 32KB)
        let original_data: Vec<u8> = (0..256u16).map(|i| (i % 256) as u8).collect();
        let original_len = original_data.len();

        // Step 2: Compress using lzxd (the crate doesn't have a compressor,
        // so test the decompression path with an uncompressed block instead).
        // LZX uncompressed blocks: type=1 (uncompressed), the lzxd crate
        // handles the decompression format. But we can't easily create
        // compressed data without a compressor. Instead, test the block
        // parsing loop with the actual try_get_exe function.

        // Construct a BaseFileFormat with LZX compression
        let bff = BaseFileFormat {
            encryption: XexEncryption::No,
            compression: XexCompression::Compressed,
            basics: vec![],
            normal: Some(NormalCompression {
                window_size: 0x8000, // 32KB
                block_size: 0,       // single block, no data
                block_hash: [0u8; 20],
            }),
        };

        // block_size=0 means the loop exits immediately, producing 0 bytes
        let empty_data: Vec<u8> = vec![];
        let result = XexInfo::try_get_exe(&empty_data, &[0u8; 16], &bff, original_len as u32);

        // With block_size=0, the loop body never executes → pos_out stays 0 → bail
        assert!(result.is_err(), "Should fail with zero output when block_size=0");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("zero output bytes"),
            "Error should mention zero output, got: {err_msg}"
        );
    }

    /// Test that Compressed case rejects truncated blocks.
    #[test]
    fn test_lzx_decompression_truncated_block() {
        let bff = BaseFileFormat {
            encryption: XexEncryption::No,
            compression: XexCompression::Compressed,
            basics: vec![],
            normal: Some(NormalCompression {
                window_size: 0x8000,
                block_size: 100, // says block is 100 bytes
                block_hash: [0u8; 20],
            }),
        };

        // Only provide 50 bytes of data, but block_size says 100
        let short_data: Vec<u8> = vec![0u8; 50];
        let result = XexInfo::try_get_exe(&short_data, &[0u8; 16], &bff, 1024);

        assert!(result.is_err(), "Should fail on truncated block");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("block needs"),
            "Error should describe block size mismatch, got: {err_msg}"
        );
    }

    /// Test that Compressed case rejects blocks too small for header.
    #[test]
    fn test_lzx_decompression_block_too_small() {
        let bff = BaseFileFormat {
            encryption: XexEncryption::No,
            compression: XexCompression::Compressed,
            basics: vec![],
            normal: Some(NormalCompression {
                window_size: 0x8000,
                block_size: 20, // block is 20 bytes, but header needs 24
                block_hash: [0u8; 20],
            }),
        };

        let small_data: Vec<u8> = vec![0u8; 20];
        let result = XexInfo::try_get_exe(&small_data, &[0u8; 16], &bff, 1024);

        assert!(result.is_err(), "Should fail when block is too small for header");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too small for header"),
            "Error should mention header size, got: {err_msg}"
        );
    }

    /// Test that a block with zero chunk_len terminates gracefully.
    #[test]
    fn test_lzx_decompression_zero_chunk_terminates() {
        let bff = BaseFileFormat {
            encryption: XexEncryption::No,
            compression: XexCompression::Compressed,
            basics: vec![],
            normal: Some(NormalCompression {
                window_size: 0x8000,
                block_size: 26, // 24 header + 2 bytes for chunk_len=0
                block_hash: [0u8; 20],
            }),
        };

        // Block layout:
        //   [0..4]  next_block_size = 0 (no more blocks)
        //   [4..24] rest of header (zeros)
        //   [24..26] chunk_len = 0 (terminates sub-chunk loop)
        let mut block = vec![0u8; 26];
        // next_block_size = 0 (big-endian)
        block[0..4].copy_from_slice(&0u32.to_be_bytes());
        // chunk_len = 0 (big-endian)
        block[24..26].copy_from_slice(&0u16.to_be_bytes());

        let result = XexInfo::try_get_exe(&block, &[0u8; 16], &bff, 1024);

        // chunk_len=0 → break out of sub-chunk loop
        // next_block_size=0 → exit main loop
        // pos_out=0 → bail("zero output bytes")
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("zero output bytes"));
    }

    /// `genuine_except_data_set` must keep an `except_data_` whose word1 is a
    /// real code-section handler VA, and reject one whose word1 is an
    /// instruction encoding (the RB3 LTCG-fragmented-.pdata false positive that
    /// corrupted byte-identical functions in the COFF).
    #[test]
    fn test_genuine_except_data_set_filters_spurious() {
        // .text at base 0x82000000, 0x20 bytes.
        //   - except_data_82000018 @ 0x82000008: word1 = 0x82000000 (a code VA
        //     within this section → genuine EH struct).
        //   - except_data_82000028 @ 0x82000010: word1 = 0x7D8802A6 (`mflr r12`,
        //     not a code VA → spurious, on top of live code).
        let base = 0x82000000u32;
        let mut data = vec![0u8; 0x20];
        data[0x08..0x0C].copy_from_slice(&0x82000000u32.to_be_bytes()); // genuine handler VA
        data[0x0C..0x10].copy_from_slice(&0x8200001Cu32.to_be_bytes()); // record VA (unused here)
        data[0x10..0x14].copy_from_slice(&0x7D8802A6u32.to_be_bytes()); // mflr r12 (spurious)
        data[0x14..0x18].copy_from_slice(&0x9181FFF8u32.to_be_bytes()); // stw r12 (spurious)

        let section = ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: base as u64,
            size: data.len() as u64,
            data,
            align: 4,
            elf_index: 0,
            relocations: ObjRelocations::default(),
            virtual_address: Some(base as u64),
            file_offset: 0,
            section_known: true,
            splits: Default::default(),
        };
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "test.exe".into(),
            vec![],
            vec![section],
        );
        for (name, addr) in [("except_data_82000018", base + 8), ("except_data_82000028", base + 0x10)]
        {
            obj.symbols
                .add_direct(ObjSymbol {
                    name: name.into(),
                    address: addr as u64,
                    section: Some(0),
                    size: 8,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    kind: ObjSymbolKind::Object,
                    ..Default::default()
                })
                .unwrap();
        }

        let set = genuine_except_data_set(&obj);
        assert!(set.contains("82000018"), "genuine EH struct (code handler VA) must be kept");
        assert!(
            !set.contains("82000028"),
            "spurious except_data on live code (instruction word1) must be rejected"
        );
    }
}

// debug only, lists section bounds
pub fn list_exe_sections(exe: &PeFile32) {
    println!("Sections:");
    for sec in exe.section_table().iter() {
        let name = std::str::from_utf8(&sec.name).unwrap_or("").trim_end_matches('\0');
        println!("Name: {}", name);
        println!("  VirtualSize: 0x{:08X}", sec.virtual_size.get(endian::LittleEndian));
        println!("  VirtualAddress: 0x{:08X}", sec.virtual_address.get(endian::LittleEndian));
        println!("  SizeOfRawData: 0x{:08X}", sec.size_of_raw_data.get(endian::LittleEndian));
        println!("  PointerToRawData: 0x{:08X}", sec.pointer_to_raw_data.get(endian::LittleEndian));
        println!(
            "  Has uninitialized data? {}",
            sec.characteristics.get(endian::LittleEndian) & 0x80 != 0
        );
        println!("");
    }
}
