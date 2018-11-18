use std::fmt;
use std::borrow::Cow;

#[derive(Debug, PartialEq, Clone)]
pub struct CheckedKey {
    inner: Vec<u8>
}

impl Into<Vec<u8>> for CheckedKey {
    fn into(self) -> Vec<u8> { self.inner }
}

impl AsRef<[u8]> for CheckedKey {
    fn as_ref(&self) -> &[u8] { &self.inner }
}

#[derive(Debug, PartialEq)]
pub enum CheckError {
    TooShort,
    TooLong,
}

use self::CheckError::*;

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TooShort => write!(f, "A key must be longer than {}", MIN_KEY_LENGTH),
            TooLong => write!(f, "A key must be shorter then {}", MAX_KEY_LENGTH),
        }
    }
}

#[cfg(debug)]
const MIN_KEY_LENGTH: usize = 3;

#[cfg(not(debug))]
const MIN_KEY_LENGTH: usize = 10;
const MAX_KEY_LENGTH: usize = 40;

pub fn check<'a, T: Into<Cow<'a, str>>>(input: T) -> Result<CheckedKey, CheckError> {
    Ok(input.into())
        .and_then(too_short)
        .and_then(too_long)
        .map(|key| CheckedKey { inner: key.into_owned().into_bytes() })
}

type Check<'a> = Result<Cow<'a, str>, CheckError>;

fn unit_check<'a, F>(input: Cow<'a, str>, test: F, err: CheckError) -> Check<'a>
    where F: FnOnce(&str) -> bool
{
    if test(&input) {
        Err(err)
    } else {
        Ok(input)
    }
}

fn too_short<'a>(input: Cow<'a, str>) -> Check<'a> {
    unit_check(input, |s| s.len() < MIN_KEY_LENGTH, TooShort)
}

fn too_long<'a>(input: Cow<'a, str>) -> Check<'a> {
    unit_check(input, |s| s.len() > MAX_KEY_LENGTH, TooLong)
}

#[cfg(test)]
mod test {
    use std::str::from_utf8;
    use crate::checked_key::{CheckError, check};

    #[test]
    fn legal_key() {
        let key = "asdf1234QWER,./";
        assert_eq!(check(key).unwrap().as_ref(), key.as_bytes());
    }

    #[test]
    fn short_key() {
        let key = "a/";
        assert_eq!(check(key), Err(CheckError::TooShort));
    }

    #[test]
    fn long_key() {
        let key = from_utf8(&[1u8; 41]).unwrap();
        assert_eq!(check(key), Err(CheckError::TooLong));
    }
}
