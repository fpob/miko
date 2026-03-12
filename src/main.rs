#![doc = include_str!("../README.md")]

use anyhow::{anyhow, bail};
use clap::{Command, CommandFactory, Parser, ValueHint};
use clap_complete::{Generator, Shell, generate};
use colored::Colorize;
use inquire::{Password, Text};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs, io,
    path::PathBuf,
    str::FromStr,
    sync::{LazyLock, mpsc},
    thread,
};

mod anidb;
mod utils;

const DEFAULT_CONFIG_NAME: &str = "config";
const DEFAULT_RENAME_FORMAT: &str = "$aname - $epno";

static DEFAULT_CONFIG_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    confy::get_configuration_file_path(clap::crate_name!(), DEFAULT_CONFIG_NAME)
        .expect("got the default config path")
});

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
    #[clap(required = true, value_hint = ValueHint::FilePath)]
    files: Vec<PathBuf>,
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
        let path = match &path {
            Some(path) if !path.exists() => {
                bail!("Config file \"{}\" does't exist", path.to_string_lossy())
            }
            Some(path) => path,
            None => &*DEFAULT_CONFIG_PATH,
        };
        confy::load_path(path).map_err(|e| anyhow!("Failed to load config, {e}"))
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

struct FileOptions<'a> {
    watched: bool,
    watched_timestamp: i64,
    deleted: bool,
    edit: bool,
    rename: bool,
    rename_format: &'a str,
}

fn print_completions<G: Generator>(generator: G, cmd: &mut Command) {
    generate(
        generator,
        cmd,
        cmd.get_name().to_string(),
        &mut io::stdout(),
    );
}

fn main() -> anyhow::Result<()> {
    if let Ok(shell) = env::var("_MIKO_GENERATE_COMPLETION") {
        let shell = Shell::from_str(&shell).expect("supported shell");
        let mut cmd = Cli::command();
        print_completions(shell, &mut cmd);
        return Ok(());
    }

    let args = Cli::parse();
    let config = Config::load(args.config)?;

    let username = args
        .username
        .or(config.username)
        .or_else(|| Text::new("Username").prompt().ok())
        .ok_or(anyhow!("Username not provided"))?;

    let password = args
        .password
        .or(config.password)
        .or_else(|| {
            Password::new("Password")
                .without_confirmation()
                .prompt()
                .ok()
        })
        .ok_or(anyhow!("Password not provided"))?;

    let encrypt_key = args.encrypt.or(config.encrypt);

    let watched_timestamp = if let Some(date) = &args.watched_date {
        utils::timestamp_from_date(date)?
    } else {
        utils::timestamp_now()
    };
    let watched = args.watched || args.watched_date.is_some();

    let rename_format = args
        .rename_format
        .or(config.rename_format)
        .unwrap_or(DEFAULT_RENAME_FORMAT.into());

    let client = create_client(&username, &password, encrypt_key.as_deref())?;

    process_files(
        &client,
        args.files,
        &FileOptions {
            watched,
            watched_timestamp,
            deleted: args.deleted,
            edit: args.edit,
            rename: args.rename,
            rename_format: &rename_format,
        },
    )
}

fn create_client(
    username: &str,
    password: &str,
    encrypt_key: Option<&str>,
) -> anyhow::Result<anidb::Client> {
    let mut client = anidb::Client::new()?;

    if let Some(encrypt_key) = encrypt_key {
        client.encrypt(username, encrypt_key)?;
    }

    client.auth(username, password)?;

    Ok(client)
}

fn process_files(
    client: &anidb::Client,
    files: Vec<PathBuf>,
    options: &FileOptions,
) -> anyhow::Result<()> {
    let (files_tx, files_rx) = mpsc::channel();
    thread::spawn(move || {
        for file in files {
            let size = fs::metadata(&file).map(|x| x.len());
            let hash = utils::file_ed2k(&file);
            let _ = files_tx.send((file, size, hash));
        }
    });

    for (file_path, file_size, file_hash) in files_rx {
        println!("{}", file_path.to_string_lossy().bold());

        let (Ok(file_size), Ok(file_hash)) = (file_size, file_hash) else {
            println!("  - failed to get file info, skipping");
            continue;
        };

        println!("  - ed2k={file_hash} size={file_size}");

        let mylistadd_response = client
            .command("MYLISTADD")
            .param("ed2k", &file_hash)
            .param("size", &file_size.to_string())
            .param("state", if options.deleted { "3" } else { "1" }) // 1 = internal storage (hdd)
            .param("viewed", if options.watched { "1" } else { "0" })
            .param("viewdate", &options.watched_timestamp.to_string())
            .param("edit", if options.edit { "1" } else { "0" })
            .send()?;

        println!("  - {}", mylistadd_response.message.to_lowercase());

        if !options.rename || mylistadd_response.code == 320 {
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

        let Ok(file_name_new) = subst::substitute(options.rename_format, &file_vars) else {
            println!("  - failed to format file name, invalid rename format");
            continue;
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
