use std::collections::VecDeque;

use archive_trait::{Archive, Member, MemberMetadata, MemberPayload, SpecialKind};
use thiserror::Error;

const MAX_TEST_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
#[error("test archive failure")]
pub struct TestError;

pub type TestEntry = Result<Member<TestPayload>, TestError>;

pub mod entry {
    use super::*;

    pub fn file(path: &str, data: impl Into<Vec<u8>>) -> TestEntry {
        file_with_options(path, data, false, false)
    }

    pub fn invalid_file(path: &str, data: impl Into<Vec<u8>>) -> TestEntry {
        file_with_options(path, data, false, true)
    }

    pub fn executable(path: &str, data: impl Into<Vec<u8>>) -> TestEntry {
        file_with_options(path, data, true, false)
    }

    fn file_with_options(
        path: &str,
        data: impl Into<Vec<u8>>,
        executable: bool,
        fail_at_end: bool,
    ) -> TestEntry {
        let data = data.into();
        Ok(Member::File {
            metadata: metadata(path),
            size: data.len() as u64,
            executable,
            payload: TestPayload::new(data, fail_at_end),
        })
    }

    pub fn directory(path: &str) -> TestEntry {
        Ok(Member::Directory {
            metadata: metadata(path),
        })
    }

    pub fn symbolic_link(path: &str, target: &str) -> TestEntry {
        Ok(Member::SymbolicLink {
            metadata: metadata(path),
            target: target.to_owned(),
        })
    }

    pub fn hard_link(path: &str, target: &str, data: impl Into<Vec<u8>>) -> TestEntry {
        let data = data.into();
        Ok(Member::HardLink {
            metadata: metadata(path),
            target: target.to_owned(),
            size: data.len() as u64,
            payload: TestPayload::new(data, false),
        })
    }

    pub fn special(path: &str, kind: SpecialKind) -> TestEntry {
        Ok(Member::Special {
            metadata: metadata(path),
            kind,
        })
    }

    pub fn error() -> TestEntry {
        Err(TestError)
    }

    fn metadata(path: &str) -> MemberMetadata {
        MemberMetadata {
            path: path.to_owned(),
            position: 0,
        }
    }
}

pub struct TestArchive {
    entries: VecDeque<TestEntry>,
}

impl TestArchive {
    pub fn new(entries: impl IntoIterator<Item = TestEntry>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }
}

pub struct TestPayload {
    data: Vec<u8>,
    offset: usize,
    fail_at_end: bool,
}

impl TestPayload {
    fn new(data: Vec<u8>, fail_at_end: bool) -> Self {
        Self {
            data,
            offset: 0,
            fail_at_end,
        }
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
            if self.fail_at_end {
                return Err(TestError);
            }
            return Ok(false);
        }
        let end = self
            .offset
            .saturating_add(target_len.clamp(1, MAX_TEST_CHUNK_BYTES))
            .min(self.data.len());
        buffer.extend_from_slice(&self.data[self.offset..end]);
        self.offset = end;
        Ok(true)
    }

    async fn skip(self) -> Result<(), Self::Error> {
        if self.fail_at_end {
            return Err(TestError);
        }
        Ok(())
    }
}

impl Archive for TestArchive {
    type Error = TestError;
    type Payload<'a> = TestPayload;

    async fn next_member<'a>(
        &'a mut self,
    ) -> Result<Option<Member<Self::Payload<'a>>>, Self::Error> {
        match self.entries.pop_front() {
            Some(entry) => entry.map(Some),
            None => Ok(None),
        }
    }
}
