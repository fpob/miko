# Miko

AniDB CLI client to add files to mylist and rename them.

## Installation

### Nix

```sh
nix run github:fpob/miko
```

You can use `stable` tag which should always point to the latest release.

```
github:fpob/miko/stable
```

### Release Binaries

You can download statically linkend binaries from the [release page](https://github.com/fpob/miko/releases)

## Usage

To get list of all available command line option, use `miko -h` for short help or `miko --help` for
more detailed help.

### Command Line Options

```
Usage: miko [OPTIONS] <FILES>...

Arguments:
  <FILES>...  Files to add to mylist

Options:
      --config <CONFIG>                Path to the config file [env:
                                       MIKO_CONFIG=/home/fpob/proj/miko/miko.toml]
      --username <USERNAME>            AniDB username: prompted if not provided via CLI or config
      --password <PASSWORD>            AniDB password: prompted if not provided via CLI or config
      --encrypt <ENCRYPT>              Optional AniDB API key for encryption: configured in your
                                       account settings
  -w, --watched                        Mark files as watched
  -W, --watched-date <WATCHED_DATE>    Mark files as watched and set watched date to the specified
                                       value
  -d, --deleted                        Set file state to deleted
  -e, --edit                           If file already exists in mylist, edit watched state, date
                                       and mylist state (on HDD or deleted)
  -r, --rename                         Rename files
      --rename-format <RENAME_FORMAT>  Format for renaming files (see more with '--help')
  -h, --help                           Print help (see more with '--help')
```

### Configuration

Options `username`, `password`, `encrypt` and `rename_format` can be set in configuration file so
you don't need to always pass them on command line.

The default config file path is displayed in the long help (`miko --help`). On Linux, it is
typically `~/.config/miko/config.toml`.

```toml
username = "username"
password = "password"
encrypt = "secret encryption key"
rename_format = "$epno - $epname - [$gsname]"
```

### Example Use

Add all mkv files to mylist, rename them and mark as watched (`r` and `w` options).

```
$ miko -rw *.mkv
> Password ********
[SubsPlease] Re Zero kara Hajimeru Isekai Seikatsu - 70 (720p) [C498699F].mkv
  - ed2k=c568dd0a6547d4fab6ca2694a132d2d9 size=741563301
  - mylist entry added
  - renamed to "04 - A White Sky Asterism - [SubsPlease].mkv"
```

With the following configuration it did not ask for username, only for password.

```toml
username = "user"
```
