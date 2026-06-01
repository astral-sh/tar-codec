use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use async_compression::tokio::bufread::GzipDecoder;
use clap::{Parser, Subcommand};
use tar_codec::decode::{Archive, ExtractError, ExtractPolicy};
use tar_framing::{
    ArchiveFormat, FrameError, GnuKind, HdrCharset, MemberKind, PaxKind, PaxRecord, PaxString,
    PaxValue,
    stream::{DataOwner, Frame, TarStream},
};
use thiserror::Error;
use tokio::{
    fs::File,
    io::{AsyncRead, BufReader},
};
use tokio_stream::StreamExt;

#[derive(Debug, Parser)]
#[command(about = "Inspect and extract tar streams")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Dump the low-level tar framing stream.
    Frames {
        /// The tar archive to inspect.
        archive: PathBuf,
    },
    /// Securely extract a tar archive.
    Extract {
        /// The tar archive to extract.
        archive: PathBuf,
        /// The directory to extract into.
        destination: PathBuf,
    },
}

#[derive(Debug, Error)]
enum CliError {
    #[error("failed to open {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Extract(#[from] ExtractError),
    #[error(transparent)]
    Framing(#[from] FrameError),
    #[error("failed to write frame dump: {0}")]
    Output(#[from] io::Error),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Frames { archive } => {
            let mut stdout = io::stdout().lock();
            dump_archive(&archive, &mut stdout).await?;
        }
        Command::Extract {
            archive,
            destination,
        } => extract_archive(&archive, &destination).await?,
    }
    Ok(())
}

async fn dump_archive<W: Write>(archive: &Path, output: &mut W) -> Result<(), CliError> {
    let file = open_archive(archive).await?;
    let label = archive.display().to_string();

    if is_gzip_tar(archive) {
        dump_frames(GzipDecoder::new(BufReader::new(file)), &label, output).await?;
    } else {
        dump_frames(file, &label, output).await?;
    }
    Ok(())
}

async fn extract_archive(archive: &Path, destination: &Path) -> Result<(), CliError> {
    let file = open_archive(archive).await?;
    if is_gzip_tar(archive) {
        extract_reader(GzipDecoder::new(BufReader::new(file)), destination).await?;
    } else {
        extract_reader(file, destination).await?;
    }
    Ok(())
}

async fn open_archive(archive: &Path) -> Result<File, CliError> {
    File::open(archive).await.map_err(|source| CliError::Open {
        path: archive.to_owned(),
        source,
    })
}

async fn extract_reader<R: AsyncRead + Unpin>(
    reader: R,
    destination: &Path,
) -> Result<(), ExtractError> {
    Archive::new(reader)
        .extract(destination, ExtractPolicy::default())
        .await
}

fn is_gzip_tar(archive: &Path) -> bool {
    archive
        .file_name()
        .is_some_and(|file_name| file_name.to_string_lossy().ends_with(".tar.gz"))
}

async fn dump_frames<R: AsyncRead + Unpin, W: Write>(
    reader: R,
    archive: &str,
    output: &mut W,
) -> Result<(), CliError> {
    let mut stream = TarStream::new(reader);
    let mut started = false;
    let mut index = 0;

    while let Some(result) = stream.next().await {
        let frame = match result {
            Ok(frame) => frame,
            Err(error) => {
                if started {
                    output.flush()?;
                }
                return Err(error.into());
            }
        };
        if !started {
            let format = stream
                .format()
                .expect("an emitted frame selects an archive format");
            render_preamble(output, archive, format_name(format))?;
            started = true;
        }
        render_frame(output, index, &frame)?;
        index += 1;
    }

    if !started {
        render_preamble(output, archive, "empty")?;
    }
    output.flush()?;
    Ok(())
}

fn render_preamble(output: &mut impl Write, archive: &str, format: &str) -> io::Result<()> {
    writeln!(output, "archive: {archive}")?;
    writeln!(output, "format: {format}")?;
    writeln!(output, "frames:")
}

fn render_frame(output: &mut impl Write, index: usize, frame: &Frame) -> io::Result<()> {
    match frame {
        Frame::Pax(frame) => writeln!(
            output,
            "    [{index}] @{} pax {} payload={}",
            frame.position,
            pax_kind_name(frame.kind),
            frame.payload_size
        ),
        Frame::Gnu(frame) => writeln!(
            output,
            "    [{index}] @{} gnu {} payload={}",
            frame.position,
            gnu_kind_name(frame.kind),
            frame.payload_size
        ),
        Frame::Header(frame) => {
            writeln!(
                output,
                "    [{index}] @{} header {} declared={} effective={} payload={}",
                frame.position,
                member_kind_name(frame.kind),
                frame.declared_size,
                frame.effective_size,
                frame.payload_size
            )?;
            render_pax_records(output, "global", &frame.global_pax_records)?;
            render_pax_records(output, "local", &frame.local_pax_records)
        }
        Frame::Data(frame) => writeln!(
            output,
            "    [{index}] @{} data owner={} len={}",
            frame.position,
            data_owner_name(frame.owner),
            frame.len
        ),
    }
}

fn render_pax_records(
    output: &mut impl Write,
    scope: &str,
    records: &[PaxRecord],
) -> io::Result<()> {
    for record in records {
        let keyword = record.keyword();
        match record {
            PaxRecord::Atime(value)
            | PaxRecord::Ctime(value)
            | PaxRecord::Gid(value)
            | PaxRecord::Mtime(value)
            | PaxRecord::Size(value)
            | PaxRecord::Uid(value) => render_pax_integer(output, scope, &keyword, value)?,
            PaxRecord::Charset(value)
            | PaxRecord::Comment(value)
            | PaxRecord::Realtime { value, .. }
            | PaxRecord::Security { value, .. }
            | PaxRecord::Vendor { value, .. } => render_pax_text(output, scope, &keyword, value)?,
            PaxRecord::Gname(value)
            | PaxRecord::LinkPath(value)
            | PaxRecord::Path(value)
            | PaxRecord::Uname(value) => render_pax_string(output, scope, &keyword, value)?,
            PaxRecord::HdrCharset(value) => render_pax_charset(output, scope, value)?,
        }
    }
    Ok(())
}

fn render_pax_text(
    output: &mut impl Write,
    scope: &str,
    keyword: &str,
    value: &PaxValue<String>,
) -> io::Result<()> {
    write!(output, "        {scope} pax: {}=", keyword.escape_default())?;
    match value {
        PaxValue::Value(value) => writeln!(output, "{value:?}"),
        PaxValue::Deleted => writeln!(output, "<deleted>"),
    }
}

fn render_pax_integer(
    output: &mut impl Write,
    scope: &str,
    keyword: &str,
    value: &PaxValue<u64>,
) -> io::Result<()> {
    write!(output, "        {scope} pax: {}=", keyword.escape_default())?;
    match value {
        PaxValue::Value(value) => writeln!(output, "{value}"),
        PaxValue::Deleted => writeln!(output, "<deleted>"),
    }
}

fn render_pax_string(
    output: &mut impl Write,
    scope: &str,
    keyword: &str,
    value: &PaxValue<PaxString>,
) -> io::Result<()> {
    write!(output, "        {scope} pax: {}=", keyword.escape_default())?;
    match value {
        PaxValue::Value(PaxString::Utf8(value)) => writeln!(output, "{value:?}"),
        PaxValue::Value(PaxString::Binary(value)) => writeln!(output, "binary({value:?})"),
        PaxValue::Deleted => writeln!(output, "<deleted>"),
    }
}

fn render_pax_charset(
    output: &mut impl Write,
    scope: &str,
    value: &PaxValue<HdrCharset>,
) -> io::Result<()> {
    write!(output, "        {scope} pax: hdrcharset=")?;
    match value {
        PaxValue::Value(HdrCharset::Utf8) => writeln!(output, "{:?}", "ISO-IR 10646 2000 UTF-8"),
        PaxValue::Value(HdrCharset::Binary) => writeln!(output, "{:?}", "BINARY"),
        PaxValue::Deleted => writeln!(output, "<deleted>"),
    }
}

fn format_name(format: ArchiveFormat) -> &'static str {
    match format {
        ArchiveFormat::Pax => "posix-pax",
        ArchiveFormat::Gnu => "gnu",
    }
}

fn pax_kind_name(kind: PaxKind) -> &'static str {
    match kind {
        PaxKind::Local => "local",
        PaxKind::Global => "global",
    }
}

fn gnu_kind_name(kind: GnuKind) -> &'static str {
    match kind {
        GnuKind::LongName => "long-name",
        GnuKind::LongLink => "long-link",
    }
}

fn member_kind_name(kind: MemberKind) -> &'static str {
    match kind {
        MemberKind::Regular => "regular",
        MemberKind::HardLink => "hard-link",
        MemberKind::SymbolicLink => "symbolic-link",
        MemberKind::CharacterDevice => "character-device",
        MemberKind::BlockDevice => "block-device",
        MemberKind::Directory => "directory",
        MemberKind::Fifo => "fifo",
        MemberKind::Contiguous => "contiguous",
    }
}

fn data_owner_name(owner: DataOwner) -> &'static str {
    match owner {
        DataOwner::Pax(PaxKind::Local) => "pax(local)",
        DataOwner::Pax(PaxKind::Global) => "pax(global)",
        DataOwner::Gnu(GnuKind::LongName) => "gnu(long-name)",
        DataOwner::Gnu(GnuKind::LongLink) => "gnu(long-link)",
        DataOwner::Member => "member",
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, ops::Range};

    use async_compression::tokio::write::GzipEncoder;
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    use super::*;

    const BLOCK_SIZE: usize = 512;
    const CHECKSUM_RANGE: Range<usize> = 148..156;
    const IDENTITY_RANGE: Range<usize> = 257..265;
    const MODE_RANGE: Range<usize> = 100..108;
    const NAME_RANGE: Range<usize> = 0..100;
    const SIZE_RANGE: Range<usize> = 124..136;
    const TYPEFLAG_OFFSET: usize = 156;
    const POSIX_IDENTITY: &[u8; 8] = b"ustar\x0000";

    #[tokio::test]
    async fn extracts_plain_tar_archive() {
        let temp = tempdir().unwrap();
        let archive = temp.path().join("archive.tar");
        let destination = temp.path().join("out");
        fs::write(&archive, archive_with_file("file", b"contents")).unwrap();

        extract_archive(&archive, &destination).await.unwrap();

        assert_eq!(fs::read(destination.join("file")).unwrap(), b"contents");
    }

    #[tokio::test]
    async fn extracts_gzip_tar_archive() {
        let temp = tempdir().unwrap();
        let archive = temp.path().join("archive.tar.gz");
        let destination = temp.path().join("out");
        let mut encoder = GzipEncoder::new(Vec::new());
        encoder
            .write_all(&archive_with_file("file", b"contents"))
            .await
            .unwrap();
        encoder.shutdown().await.unwrap();
        fs::write(&archive, encoder.into_inner()).unwrap();

        extract_archive(&archive, &destination).await.unwrap();

        assert_eq!(fs::read(destination.join("file")).unwrap(), b"contents");
    }

    #[tokio::test]
    async fn reports_extraction_failure() {
        let temp = tempdir().unwrap();
        let archive = temp.path().join("invalid.tar");
        let destination = temp.path().join("out");
        fs::write(&archive, [0xff; BLOCK_SIZE]).unwrap();

        assert!(matches!(
            extract_archive(&archive, &destination).await.unwrap_err(),
            CliError::Extract(ExtractError::Framing(_))
        ));
    }

    fn archive_with_file(path: &str, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut header = [0; BLOCK_SIZE];
        header[NAME_RANGE.start..NAME_RANGE.start + path.len()].copy_from_slice(path.as_bytes());
        header[MODE_RANGE].copy_from_slice(b"0000644\0");
        let size = format!("{:011o}\0", payload.len());
        header[SIZE_RANGE].copy_from_slice(size.as_bytes());
        header[TYPEFLAG_OFFSET] = b'0';
        header[IDENTITY_RANGE].copy_from_slice(POSIX_IDENTITY);
        set_checksum(&mut header);
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().next_multiple_of(BLOCK_SIZE), 0);
        bytes.resize(bytes.len() + 2 * BLOCK_SIZE, 0);
        bytes
    }

    fn set_checksum(block: &mut [u8; BLOCK_SIZE]) {
        block[CHECKSUM_RANGE].fill(b' ');
        let checksum = block.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        let encoded = format!("{checksum:06o}\0 ");
        block[CHECKSUM_RANGE].copy_from_slice(encoded.as_bytes());
    }
}
