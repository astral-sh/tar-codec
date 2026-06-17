use std::collections::VecDeque;

use archive_trait::{Archive, Member, MemberMetadata, MemberPayload, SpecialKind};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("test archive failure")]
pub struct TestError;

pub enum Entry {
    File {
        position: u64,
        path: String,
        data: Vec<u8>,
        executable: bool,
    },
    Directory {
        position: u64,
        path: String,
    },
    SymbolicLink {
        position: u64,
        path: String,
        target: String,
    },
    HardLink {
        position: u64,
        path: String,
        target: String,
        data: Vec<u8>,
    },
    Special {
        position: u64,
        path: String,
        kind: SpecialKind,
    },
    Error,
}

impl Entry {
    pub fn file(path: &str, data: impl Into<Vec<u8>>) -> Self {
        Self::File {
            position: 0,
            path: path.to_owned(),
            data: data.into(),
            executable: false,
        }
    }

    pub fn executable(path: &str, data: impl Into<Vec<u8>>) -> Self {
        Self::File {
            position: 0,
            path: path.to_owned(),
            data: data.into(),
            executable: true,
        }
    }

    pub fn directory(path: &str) -> Self {
        Self::Directory {
            position: 0,
            path: path.to_owned(),
        }
    }

    pub fn symbolic_link(path: &str, target: &str) -> Self {
        Self::SymbolicLink {
            position: 0,
            path: path.to_owned(),
            target: target.to_owned(),
        }
    }

    pub fn hard_link(path: &str, target: &str, data: impl Into<Vec<u8>>) -> Self {
        Self::HardLink {
            position: 0,
            path: path.to_owned(),
            target: target.to_owned(),
            data: data.into(),
        }
    }

    pub fn special(path: &str, kind: SpecialKind) -> Self {
        Self::Special {
            position: 0,
            path: path.to_owned(),
            kind,
        }
    }
}

pub struct TestArchive {
    entries: VecDeque<Entry>,
}

impl TestArchive {
    pub fn new(entries: impl IntoIterator<Item = Entry>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }
}

pub struct TestPayload {
    data: Vec<u8>,
    offset: usize,
}

impl TestPayload {
    fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }
}

impl MemberPayload for TestPayload {
    type Error = TestError;

    async fn next_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, Self::Error> {
        buffer.clear();
        if self.offset == self.data.len() {
            return Ok(false);
        }
        let end = self
            .offset
            .saturating_add(target_len.max(1))
            .min(self.data.len());
        buffer.extend_from_slice(&self.data[self.offset..end]);
        self.offset = end;
        Ok(true)
    }

    async fn skip(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Archive for TestArchive {
    type Error = TestError;
    type Payload<'a> = TestPayload;

    async fn next_member(&mut self) -> Result<Option<Member<Self::Payload<'_>>>, Self::Error> {
        let Some(entry) = self.entries.pop_front() else {
            return Ok(None);
        };
        if matches!(entry, Entry::Error) {
            return Err(TestError);
        }
        Ok(Some(match entry {
            Entry::File {
                position,
                path,
                data,
                executable,
            } => Member::File {
                metadata: MemberMetadata { path, position },
                size: data.len() as u64,
                executable,
                payload: TestPayload::new(data),
            },
            Entry::Directory { position, path } => Member::Directory {
                metadata: MemberMetadata { path, position },
            },
            Entry::SymbolicLink {
                position,
                path,
                target,
            } => Member::SymbolicLink {
                metadata: MemberMetadata { path, position },
                target,
            },
            Entry::HardLink {
                position,
                path,
                target,
                data,
            } => Member::HardLink {
                metadata: MemberMetadata { path, position },
                target,
                size: data.len() as u64,
                payload: TestPayload::new(data),
            },
            Entry::Special {
                position,
                path,
                kind,
            } => Member::Special {
                metadata: MemberMetadata { path, position },
                kind,
            },
            Entry::Error => return Err(TestError),
        }))
    }
}
