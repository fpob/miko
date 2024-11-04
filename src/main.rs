#![doc = include_str!("../README.md")]

use clap::Parser;
use colored::Colorize;
use inquire::{Password, Text};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::{collections::HashMap, fs, path::Path};

mod anidb;
mod utils;

const DEFAULT_CONFIG_NAME: &str = "config";
const DEFAULT_RENAME_FORMAT: &str = "$aname - $epno";

lazy_static! {
    static ref DEFAULT_CONFIG_PATH: PathBuf =
        confy::get_configuration_file_path(clap::crate_name!(), DEFAULT_CONFIG_NAME)
            .expect("got the default config path");
}

#[derive(Parser)]
#[command(max_term_width = 100)]
struct Cli {
    /// Path to the config file.
    #[arg(
        long,
        env = "MIKO_CONFIG",
        long_help = format!("Path to the TOML config file.\n\n\
            Available options:\n\
            - username\n\
            - password\n\
            - encrypt\n\
            - rename_format\n\
            \nDefault: {:?}",
            *DEFAULT_CONFIG_PATH)
    )]
    config: Option<PathBuf>,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    encrypt: Option<String>,
    /// Mark files as watched.
    #[arg(short, long, default_value_t = false)]
    watched: bool,
    /// Mark files as watched and set watched date to the specified value.
    #[arg(short = 'W', long)]
    watched_date: Option<String>,
    /// Set file state to deleted.
    #[arg(short, long, default_value_t = false)]
    deleted: bool,
    /// If file already exists in mylist, edit watched state, date and mylist state (on HDD or
    /// deleted).
    #[arg(short, long, default_value_t = false)]
    edit: bool,
    /// Rename files.
    #[arg(short, long, default_value_t = false)]
    rename: bool,
    /// Format for renaming files (see more with '--help').
    #[arg(
        long,
        long_help = format!("Format for renaming files.\n\n\
            Available tokens:\n\
            - $fid, $aid, $eid, $gid, $lid -- AniDB IDs for the file, anime, episode, group, \
                mylist entry\n\
            - $md5, $sha1, $crc32 -- file hashes from the AniDB\n\
            - $ayear -- year the anime was airing\n\
            - $atype -- anime type, TV Series / Movie / Web / ...\n\
            - $aname, $aname_kanji, $aname_english -- anime title in romaji, kanji, english\n\
            - $epno -- episode number\n\
            - $epname -- episode name in english, romaji, kanji\n\
            - $gname -- group that released the episode file (eg. SubsPlease)\n\
            - $gsname -- short group name\n\n\
            Default: {DEFAULT_RENAME_FORMAT:?}
            "),
    )]
    rename_format: Option<String>,
    /// Files to add to mylist.
    #[clap(required = true)]
    files: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct Config {
    username: Option<String>,
    password: Option<String>,
    encrypt: Option<String>,
    rename_format: Option<String>,
}

impl Config {
    fn load(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let path = path.as_ref().unwrap_or(&DEFAULT_CONFIG_PATH);
        confy::load_path(path).map_err(|e| anyhow::anyhow!(format!("Failed to load config, {e}")))
    }
}

// Parameters for FILE command.
const FILE_FMASK: &str = "78380000";
const FILE_AMASK: &str = "30E0F0C0";
// Data keys in FILE command response.
const FILE_KEYS: &[&str] = &[
    "fid",
    "aid",
    "eid",
    "gid",
    "lid",
    "md5",
    "sha1",
    "crc32",
    "ayear",
    "atype",
    "aname",
    "aname_kanji",
    "aname_english",
    "epno",
    "epname",
    "epname_romaji",
    "epname_kanji",
    "gname",
    "gsname",
];

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let config = Config::load(args.config)?;

    let username = args
        .username
        .or(config.username)
        .or_else(|| Text::new("Username").prompt().ok())
        .ok_or(anyhow::anyhow!("Username not provided"))?;

    let password = args
        .password
        .or(config.password)
        .or_else(|| {
            Password::new("Password")
                .without_confirmation()
                .prompt()
                .ok()
        })
        .ok_or(anyhow::anyhow!("Password not provided"))?;

    let watched_timestamp = if let Some(date) = &args.watched_date {
        utils::timestamp_from_date(date)?
    } else {
        utils::timestamp_now()
    };

    let rename_format = args
        .rename_format
        .or(config.rename_format)
        .unwrap_or(DEFAULT_RENAME_FORMAT.into());

    let mut client = anidb::Client::new()?;

    if let Some(encrypt_key) = args.encrypt.or(config.encrypt) {
        client.encrypt(&username, &encrypt_key)?;
    }

    client.auth(&username, &password)?;

    let (files_tx, files_rx) = mpsc::channel();
    thread::spawn(move || {
        for file in args.files {
            let path = Path::new(&file).to_owned();
            let size = fs::metadata(&path).map(|x| x.len());
            let hash = utils::file_ed2k(&path);
            let _ = files_tx.send((file, path, size, hash));
        }
    });

    for (file_name, file_path, file_size, file_hash) in files_rx {
        println!("{}", file_name.bold());

        let (Ok(file_size), Ok(file_hash)) = (file_size, file_hash) else {
            println!("  - failed to get file info, skipping");
            continue;
        };

        println!("  - ed2k={file_hash} size={file_size}");

        let mylistadd_response = client
            .command("MYLISTADD")
            .param("ed2k", &file_hash)
            .param("size", &file_size.to_string())
            .param("state", if args.deleted { "3" } else { "1" }) // 1 = internal storage (hdd)
            .param("viewed", if args.watched { "1" } else { "0" })
            .param("viewdate", &watched_timestamp.to_string())
            .param("edit", if args.edit { "1" } else { "0" })
            .send()?;

        println!("  - {}", mylistadd_response.message.to_lowercase());

        if !args.rename || mylistadd_response.code == 320 {
            continue;
        }

        let file_response = client
            .command("FILE")
            .param("ed2k", &file_hash)
            .param("size", &file_size.to_string())
            .param("fmask", FILE_FMASK)
            .param("amask", FILE_AMASK)
            .send()?;

        let file_vars: HashMap<&str, &str> = FILE_KEYS
            .iter()
            .enumerate()
            .map(|(i, &key)| (key, file_response.data[0][i].as_str()))
            .collect();

        let Ok(file_name_new) = subst::substitute(&rename_format, &file_vars) else {
            anyhow::bail!("Failed to format file name");
        };

        let file_path_new =
            utils::change_file_stem(&file_path, &utils::sanitize_filename(&file_name_new));

        match utils::safe_rename(&file_path, &file_path_new) {
            Ok(_) => println!("  - renamed to {file_path_new:?}"),
            Err(e) => println!("  - failed to rename, {e}"),
        }
    }

    Ok(())
}
