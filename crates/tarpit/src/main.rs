use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use async_compression::tokio::bufread::GzipDecoder;
use clap::{Parser, Subcommand};
use tar_framing::{
    ArchiveFormat, DataOwner, Frame, FrameError, GnuKind, MemberKind, PaxKind, PaxRecord, PaxValue,
    TarStream,
};
use thiserror::Error;
use tokio::{
    fs::File,
    io::{AsyncRead, BufReader},
};
use tokio_stream::StreamExt;

#[derive(Debug, Parser)]
#[command(about = "Inspect tar stream representations")]
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
    Dump(#[from] DumpError),
}

#[derive(Debug, Error)]
enum DumpError {
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
    }
    Ok(())
}

async fn dump_archive<W: Write>(archive: &Path, output: &mut W) -> Result<(), CliError> {
    let file = File::open(archive).await.map_err(|source| CliError::Open {
        path: archive.to_owned(),
        source,
    })?;
    let label = archive.display().to_string();

    if is_gzip_tar(archive) {
        dump_frames(GzipDecoder::new(BufReader::new(file)), &label, output).await?;
    } else {
        dump_frames(file, &label, output).await?;
    }
    Ok(())
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
) -> Result<(), DumpError> {
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
            let effective_size = frame
                .effective_size
                .map_or_else(|| "<deleted>".to_owned(), |size| size.to_string());
            writeln!(
                output,
                "    [{index}] @{} header {} declared={} effective={} payload={}",
                frame.position,
                member_kind_name(frame.kind),
                frame.declared_size,
                effective_size,
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
        match record {
            PaxRecord::Atime(value) => render_pax_integer(output, scope, "atime", value)?,
            PaxRecord::Charset(value) => render_pax_text(output, scope, "charset", value)?,
            PaxRecord::Comment(value) => render_pax_text(output, scope, "comment", value)?,
            PaxRecord::Gid(value) => render_pax_integer(output, scope, "gid", value)?,
            PaxRecord::Gname(value) => render_pax_text(output, scope, "gname", value)?,
            PaxRecord::HdrCharset(value) => render_pax_text(output, scope, "hdrcharset", value)?,
            PaxRecord::LinkPath(value) => render_pax_text(output, scope, "linkpath", value)?,
            PaxRecord::Mtime(value) => render_pax_integer(output, scope, "mtime", value)?,
            PaxRecord::Path(value) => render_pax_text(output, scope, "path", value)?,
            PaxRecord::Realtime { name, value } => {
                render_pax_text(output, scope, &format!("realtime.{name}"), value)?;
            }
            PaxRecord::Security { name, value } => {
                render_pax_text(output, scope, &format!("security.{name}"), value)?;
            }
            PaxRecord::Size(value) => render_pax_integer(output, scope, "size", value)?,
            PaxRecord::Uid(value) => render_pax_integer(output, scope, "uid", value)?,
            PaxRecord::Uname(value) => render_pax_text(output, scope, "uname", value)?,
            PaxRecord::Vendor {
                vendor,
                name,
                value,
            } => {
                render_pax_text(output, scope, &format!("{vendor}.{name}"), value)?;
            }
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

fn format_name(format: ArchiveFormat) -> &'static str {
    match format {
        ArchiveFormat::PosixPax => "posix-pax",
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
