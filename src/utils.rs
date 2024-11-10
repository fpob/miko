use anyhow::{anyhow, bail};
use chrono::{Local, NaiveDate};
use ed2k::digest::Digest;
use ed2k::Ed2kRed;
use regex::Regex;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

/// Calculates the Ed2k hash of the file and returns it as string.
pub fn file_ed2k<P: AsRef<Path>>(path: P) -> anyhow::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut hasher = Ed2kRed::new();
    let mut buffer = [0; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let digest = hasher.finalize();

    Ok(format!("{digest:x}"))
}

/// Sanitize string to be a valid file name.
pub fn sanitize_filename(filename: &str) -> String {
    // Replace all `/` with `-`
    let filename = filename.replace('/', "-");
    // Replace leading `.` with `_`.
    let filename = Regex::new(r"^\.").unwrap().replace_all(&filename, "_");
    // Replace multiple whitespaces with a single space.
    let filename = Regex::new(r"\s+").unwrap().replace_all(&filename, " ");

    filename.to_string()
}

/// Get current datetime as unix timestamp.
pub fn timestamp_now() -> i64 {
    Local::now().timestamp()
}

/// Convert date in format `YYYY-MM-DD` to unix timestamp. Time is filled in as midnight (00:00:00)
/// in local timezone.
pub fn timestamp_from_date(date: &str) -> anyhow::Result<i64> {
    let timestamp = date
        .parse::<NaiveDate>()
        .map_err(|_| anyhow!("date must be in format YYYY-MM-DDD"))?
        .and_hms_opt(0, 0, 0)
        .ok_or(anyhow!("date is not valid"))?
        .and_local_timezone(Local::now().timezone())
        .unwrap()
        .timestamp();
    Ok(timestamp)
}

/// Change file_stem in a Path.
pub fn change_file_stem<P: AsRef<Path>>(path: P, stem: &str) -> PathBuf {
    let file = path.as_ref();
    let mut new = file.to_owned();
    new.set_file_name(stem);
    if let Some(ext) = file.extension() {
        new.set_extension(ext);
    }
    new
}

/// Rename a file, fail if `to` already exists.
pub fn safe_rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> anyhow::Result<()> {
    let to = to.as_ref();
    if to.exists() {
        bail!("file {to:?} exists");
    }
    fs::rename(from, to).map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_hidden() {
        assert_eq!(sanitize_filename(".foo"), "_foo");
    }

    #[test]
    fn sanitize_slash() {
        assert_eq!(sanitize_filename("foo/bar"), "foo-bar");
    }

    #[test]
    fn sanitize_whitespaces() {
        assert_eq!(sanitize_filename("foo\t bar"), "foo bar");
    }

    #[test]
    fn change_file_stem_no_ext() {
        assert_eq!(
            change_file_stem(&PathBuf::from("/foo/bar"), "xyz"),
            PathBuf::from("/foo/xyz")
        )
    }

    #[test]
    fn change_file_stem_keep_ext() {
        assert_eq!(
            change_file_stem(&PathBuf::from("/foo/bar.tar"), "xyz"),
            PathBuf::from("/foo/xyz.tar")
        )
    }
}
