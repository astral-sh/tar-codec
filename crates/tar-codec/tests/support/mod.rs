use tar_framing::{
    BLOCK_SIZE, Block, PaxKeyword,
    header::{
        CHECKSUM_RANGE, GID_RANGE, GNU_IDENTITY, IDENTITY_RANGE, LINK_NAME_RANGE, MODE_RANGE,
        MTIME_RANGE, NAME_RANGE, PREFIX_RANGE, SIZE_RANGE, TYPEFLAG_OFFSET, UID_RANGE,
        USTAR_IDENTITY,
    },
    write::append_pax_record,
};

#[derive(Clone, Copy)]
pub enum ArchiveFormat {
    Pax,
    Gnu,
}

#[derive(Clone, Copy)]
pub enum EntryKind {
    File,
    Directory,
    SymbolicLink,
    HardLink,
}

#[derive(Default)]
pub struct ArchiveBuilder {
    bytes: Vec<u8>,
}

impl ArchiveBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ustar(
        &mut self,
        name: &str,
        typeflag: u8,
        payload: &[u8],
        link_name: &str,
        mode: u32,
    ) -> &mut Self {
        self.member(ArchiveFormat::Pax, name, typeflag, payload, link_name, mode)
    }

    pub fn gnu(
        &mut self,
        name: &str,
        typeflag: u8,
        payload: &[u8],
        link_name: &str,
        mode: u32,
    ) -> &mut Self {
        self.member(ArchiveFormat::Gnu, name, typeflag, payload, link_name, mode)
    }

    pub fn entry(&mut self, name: &str, kind: EntryKind, payload: &[u8]) -> &mut Self {
        let (typeflag, payload, link_name) = match kind {
            EntryKind::File => (b'0', payload, ""),
            EntryKind::Directory => (b'5', &[][..], ""),
            EntryKind::SymbolicLink => (b'2', &[][..], "target"),
            EntryKind::HardLink => (b'1', &[][..], "target"),
        };
        self.ustar(name, typeflag, payload, link_name, 0o644)
    }

    pub fn pax(&mut self, typeflag: u8, payload: &[u8]) -> &mut Self {
        self.ustar("pax", typeflag, payload, "", 0o644)
    }

    pub fn block(&mut self, block: &Block) -> &mut Self {
        self.bytes.extend_from_slice(block);
        self
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.bytes.resize(self.bytes.len() + 2 * BLOCK_SIZE, 0);
        self.bytes
    }

    pub fn into_unterminated(self) -> Vec<u8> {
        self.bytes
    }

    fn member(
        &mut self,
        format: ArchiveFormat,
        name: &str,
        typeflag: u8,
        payload: &[u8],
        link_name: &str,
        mode: u32,
    ) -> &mut Self {
        self.block(&header(
            format,
            name,
            typeflag,
            payload.len() as u64,
            link_name,
            mode,
        ));
        self.bytes.extend_from_slice(payload);
        self.bytes
            .resize(self.bytes.len().next_multiple_of(BLOCK_SIZE), 0);
        self
    }
}

pub fn single_pax_member(
    name: &str,
    typeflag: u8,
    payload: &[u8],
    link_name: &str,
    mode: u32,
) -> Vec<u8> {
    let mut archive = ArchiveBuilder::new();
    archive.ustar(name, typeflag, payload, link_name, mode);
    archive.finish()
}

pub fn header(
    format: ArchiveFormat,
    name: &str,
    typeflag: u8,
    size: u64,
    link_name: &str,
    mode: u32,
) -> Block {
    let mut block = [0; BLOCK_SIZE];
    set_text(&mut block[NAME_RANGE], name);
    block[MODE_RANGE].copy_from_slice(format!("{mode:07o}\0").as_bytes());
    block[UID_RANGE].copy_from_slice(b"0000000\0");
    block[GID_RANGE].copy_from_slice(b"0000000\0");
    block[SIZE_RANGE].copy_from_slice(format!("{size:011o}\0").as_bytes());
    block[MTIME_RANGE].copy_from_slice(b"00000000000\0");
    block[TYPEFLAG_OFFSET] = typeflag;
    set_text(&mut block[LINK_NAME_RANGE], link_name);
    block[IDENTITY_RANGE].copy_from_slice(match format {
        ArchiveFormat::Pax => USTAR_IDENTITY,
        ArchiveFormat::Gnu => GNU_IDENTITY,
    });
    set_checksum(&mut block);
    block
}

pub fn set_checksum(block: &mut Block) {
    block[CHECKSUM_RANGE].fill(b' ');
    let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
    block[CHECKSUM_RANGE].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
}

pub fn set_identity_byte(block: &mut Block, index: usize, byte: u8) {
    block[IDENTITY_RANGE.start + index] = byte;
}

pub fn set_ustar_path(block: &mut Block, prefix: &str, name: &str) {
    block[NAME_RANGE].fill(0);
    set_text(&mut block[NAME_RANGE], name);
    block[PREFIX_RANGE].fill(0);
    set_text(&mut block[PREFIX_RANGE], prefix);
    set_checksum(block);
}

pub fn pax_record(keyword: PaxKeyword, value: &str) -> Vec<u8> {
    raw_pax_record(keyword, value.as_bytes())
}

pub fn raw_pax_record(keyword: PaxKeyword, value: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    append_pax_record(&mut record, &keyword, value)
        .expect("test PAX record keyword should be valid");
    record
}

fn set_text(field: &mut [u8], value: &str) {
    assert!(value.len() < field.len());
    field[..value.len()].copy_from_slice(value.as_bytes());
}

#[cfg(unix)]
pub use std::os::unix::fs::{symlink as symlink_file, symlink as symlink_dir};
#[cfg(windows)]
pub use std::os::windows::fs::{symlink_dir, symlink_file};
