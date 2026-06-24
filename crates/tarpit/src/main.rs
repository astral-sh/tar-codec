use std::{
    future::poll_fn,
    io::{self, Write},
    path::{Path, PathBuf},
    pin::Pin,
    process::ExitCode,
};

use async_compression::tokio::bufread::GzipDecoder;
use clap::{Parser, Subcommand};
use futures_core::Stream;
use tar_codec::{Archive as _, DecodeError, ExtractError, TarArchive, extract::ExtractPolicy};
use tar_framing::{
    ArchiveFormat, FrameError, GnuKind, HdrCharset, PaxKind, PaxRecord, PaxString, PaxValue,
    UstarKind,
    stream::{DataOwner, Frame, TarStream},
};
use thiserror::Error;
use tokio::{
    fs::File,
    io::{AsyncRead, BufReader},
};

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
    Extract(#[from] ExtractError<DecodeError>),
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
        TarArchive::new(GzipDecoder::new(BufReader::new(file)))
            .extract_in(destination, ExtractPolicy::default())
            .await?;
    } else {
        TarArchive::new(file)
            .extract_in(destination, ExtractPolicy::default())
            .await?;
    }
    Ok(())
}

async fn open_archive(archive: &Path) -> Result<File, CliError> {
    File::open(archive).await.map_err(|source| CliError::Open {
        path: archive.to_owned(),
        source,
    })
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

    while let Some(result) =
        poll_fn(|context| Stream::poll_next(Pin::new(&mut stream), context)).await
    {
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
        Frame::Header(frame) => writeln!(
            output,
            "    [{index}] @{} header {} declared={} effective={}",
            frame.position,
            member_kind_name(frame.kind),
            frame.declared_size,
            frame.effective_size
        ),
        Frame::Data(frame) => {
            writeln!(
                output,
                "    [{index}] @{} data owner={} len={}",
                frame.position,
                data_owner_name(frame.owner),
                frame.len
            )?;
            if let DataOwner::Pax(kind) = frame.owner
                && let Some(records) = frame.completed_pax_records()
            {
                render_pax_records(output, pax_kind_name(kind), records)?;
            }
            Ok(())
        }
    }
}

fn render_pax_records(
    output: &mut impl Write,
    scope: &str,
    records: &[PaxRecord],
) -> io::Result<()> {
    for record in records {
        let keyword = record.keyword();
        write!(output, "        {scope} pax: {keyword}=")?;
        match record {
            PaxRecord::Atime(value)
            | PaxRecord::Ctime(value)
            | PaxRecord::Gid(value)
            | PaxRecord::Mtime(value)
            | PaxRecord::Size(value)
            | PaxRecord::Uid(value) => {
                render_pax_value(output, value, |output, value| writeln!(output, "{value}"))?
            }
            PaxRecord::Charset(value)
            | PaxRecord::Comment(value)
            | PaxRecord::Realtime { value, .. }
            | PaxRecord::Security { value, .. } => {
                render_pax_value(output, value, |output, value| writeln!(output, "{value:?}"))?
            }
            PaxRecord::Vendor { value, .. } => render_pax_value(output, value, |output, value| {
                writeln!(output, "bytes({value:?})")
            })?,
            PaxRecord::Gname(value)
            | PaxRecord::LinkPath(value)
            | PaxRecord::Path(value)
            | PaxRecord::Uname(value) => {
                render_pax_value(output, value, |output, value| match value {
                    PaxString::Utf8(value) => writeln!(output, "{value:?}"),
                    PaxString::Binary(value) => writeln!(output, "binary({value:?})"),
                })?
            }
            PaxRecord::HdrCharset(value) => {
                render_pax_value(output, value, |output, value| match value {
                    HdrCharset::Utf8 => writeln!(output, "{:?}", "ISO-IR 10646 2000 UTF-8"),
                    HdrCharset::Binary => writeln!(output, "{:?}", "BINARY"),
                })?
            }
        }
    }
    Ok(())
}

fn render_pax_value<W: Write, T>(
    output: &mut W,
    value: &PaxValue<T>,
    render_value: impl FnOnce(&mut W, &T) -> io::Result<()>,
) -> io::Result<()> {
    match value {
        PaxValue::Value(value) => render_value(output, value),
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

fn member_kind_name(kind: UstarKind) -> &'static str {
    match kind {
        UstarKind::Regular => "regular",
        UstarKind::HardLink => "hard-link",
        UstarKind::SymbolicLink => "symbolic-link",
        UstarKind::CharacterDevice => "character-device",
        UstarKind::BlockDevice => "block-device",
        UstarKind::Directory => "directory",
        UstarKind::Fifo => "fifo",
        UstarKind::Contiguous => "contiguous",
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
