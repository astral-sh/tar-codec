from collections.abc import Sequence
from os import PathLike
from types import TracebackType
from typing import (
    ClassVar,
    Final,
    Iterator,
    Protocol,
    TypeAlias,
    overload,
)

class _BinaryReader(Protocol):
    def read(self, size: int, /) -> bytes | bytearray | memoryview: ...

class _BinaryWriter(Protocol):
    def write(self, data: bytes | memoryview, /) -> int: ...

ArchiveSource: TypeAlias = (
    bytes | bytearray | memoryview | str | PathLike[str] | _BinaryReader
)
ArchiveSink: TypeAlias = str | PathLike[str] | _BinaryWriter
__version__: str
__all__: tuple[str, ...]

class DecodeError(Exception): ...
class EncodeError(Exception): ...
class BuildError(Exception): ...
class ExtractError(Exception): ...
class InvalidatedPayloadError(RuntimeError): ...

class MemberKind:
    FILE: ClassVar[MemberKind]
    DIRECTORY: ClassVar[MemberKind]
    SYMBOLIC_LINK: ClassVar[MemberKind]
    HARD_LINK: ClassVar[MemberKind]
    CHARACTER_DEVICE: ClassVar[MemberKind]
    BLOCK_DEVICE: ClassVar[MemberKind]
    FIFO: ClassVar[MemberKind]

class PaxVendorExtensionPolicy:
    REJECT_UNKNOWN: ClassVar[PaxVendorExtensionPolicy]
    ALLOW_UNKNOWN: ClassVar[PaxVendorExtensionPolicy]

    @staticmethod
    def ignore(vendors: Sequence[str]) -> PaxVendorExtensionPolicy: ...

class PaxDecodePolicy:
    def __init__(
        self,
        *,
        max_extension_size: int = ...,
        max_global_extensions_size: int = ...,
        allow_non_utf8_pax_vendor_values: bool = ...,
        allow_global_pax_extensions: bool = ...,
        vendor_extension_policy: PaxVendorExtensionPolicy | None = ...,
        allow_duplicate_pax_records: bool = ...,
        allow_global_pax_member_metadata: bool = ...,
    ) -> None: ...
    max_extension_size: Final[int]
    max_global_extensions_size: Final[int]
    allow_non_utf8_pax_vendor_values: Final[bool]
    allow_global_pax_extensions: Final[bool]
    vendor_extension_policy: Final[PaxVendorExtensionPolicy]
    allow_duplicate_pax_records: Final[bool]
    allow_global_pax_member_metadata: Final[bool]

class DecodePolicy:
    def __init__(
        self,
        *,
        allow_gnu: bool = ...,
        allow_all_nul_numeric_fields: bool = ...,
        max_gnu_extension_size: int = ...,
        pax_policy: PaxDecodePolicy | None = ...,
    ) -> None: ...
    allow_gnu: Final[bool]
    allow_all_nul_numeric_fields: Final[bool]
    max_gnu_extension_size: Final[int]
    pax_policy: Final[PaxDecodePolicy]

class BuildSymlinkPolicy:
    REJECT: ClassVar[BuildSymlinkPolicy]
    PRESERVE: ClassVar[BuildSymlinkPolicy]

class ExtractSymlinkPolicy:
    PRESERVE: ClassVar[ExtractSymlinkPolicy]
    SKIP: ClassVar[ExtractSymlinkPolicy]
    REJECT: ClassVar[ExtractSymlinkPolicy]

class BuilderPolicy:
    def __init__(
        self,
        *,
        validate_names: bool = ...,
        symlink_policy: BuildSymlinkPolicy | None = ...,
    ) -> None: ...
    validate_names: Final[bool]
    symlink_policy: Final[BuildSymlinkPolicy]

class LinkPolicy:
    def __init__(
        self,
        *,
        symlink_policy: ExtractSymlinkPolicy | None = ...,
        allow_hard_links: bool = ...,
        allow_ambient_targets: bool = ...,
        allow_missing_targets: bool = ...,
    ) -> None: ...
    symlink_policy: Final[ExtractSymlinkPolicy]
    allow_hard_links: Final[bool]
    allow_ambient_targets: Final[bool]
    allow_missing_targets: Final[bool]

class ExtractPolicy:
    def __init__(
        self,
        *,
        link_policy: LinkPolicy | None = ...,
        allow_overwrites: bool = ...,
        validate_names: bool = ...,
    ) -> None: ...
    link_policy: Final[LinkPolicy]
    allow_overwrites: Final[bool]
    validate_names: Final[bool]

class MemberPayload:
    def read(self, size: int = ...) -> memoryview: ...

class Member:
    kind: Final[MemberKind]
    path: Final[str]
    size: Final[int | None]
    executable: Final[bool | None]
    target: Final[str | None]
    payload: Final[MemberPayload | None]

class TarArchive(Iterator[Member]):
    def __init__(
        self,
        source: ArchiveSource,
        policy: DecodePolicy | None = ...,
    ) -> None: ...
    def __enter__(self) -> TarArchive: ...
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
    def __iter__(self) -> TarArchive: ...
    def __next__(self) -> Member: ...
    def extract_in(
        self,
        destination: str | PathLike[str],
        policy: ExtractPolicy | None = ...,
    ) -> None: ...
    def close(self) -> None: ...

class Builder:
    def __init__(
        self, sink: ArchiveSink, policy: BuilderPolicy | None = ...
    ) -> None: ...
    def __enter__(self) -> Builder: ...
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
    @overload
    def add_file(
        self,
        path: str | PathLike[str],
        payload: bytes | bytearray | memoryview | str | PathLike[str],
        *,
        executable: bool = ...,
    ) -> None: ...
    @overload
    def add_file(
        self,
        path: str | PathLike[str],
        payload: _BinaryReader,
        *,
        size: int,
        executable: bool = ...,
    ) -> None: ...
    def add_directory(self, path: str | PathLike[str]) -> None: ...
    def add_directory_all(self, source: str | PathLike[str]) -> None: ...
    def close(self) -> None: ...
