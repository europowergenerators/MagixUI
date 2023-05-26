use anyhow::Context;
use std::{
    error::Error,
    ffi::{CString, OsString},
    path::PathBuf,
};
use windows::{h, Win32::System::Threading::OpenProcessToken};

macro_rules! HELP {
    () => {
"\
MagixUI

USAGE:
    {bin_name} [FLAGS] [OPTIONS] ProcessPath -- ProcessArgument1 ProcessArgument2 ProcessArgumentN

FLAGS:
    -h, --help            Prints help information

OPTIONS:
    --username        STRING      Start process as this user
    --domain          STRING      Specifies the domain against which username must be resolved
    --password        STRING      Use this password to logon the provided user

ARGS:
    ProcessPath       PATH        The location of the process to execute
    --
    ProcessArgumentN  STRING      Arguments passed to the proces on start
"
    };
}

struct GlobalArguments {
    username: OsString,
    domain: Option<OsString>,
    password: OsString,
    process_path: PathBuf,
    process_arguments: Vec<OsString>,
}

fn main() -> anyhow::Result<()> {
    let args = parse_args().context("Failed to parse command line arguments")?;
    unsafe { start_interactive_client_process(args) }
}

fn parse_args() -> Result<GlobalArguments, lexopt::Error> {
    use lexopt::prelude::*;

    let mut username = None;
    let mut domain = None;
    let mut password = None;
    let mut process_path = None;
    let mut other_arguments = None;

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                let bin_name = parser.bin_name().unwrap_or("MagixUI.exe");
                println!(HELP!(), bin_name = bin_name);
                std::process::exit(0);
            }
            Long("username") if other_arguments.is_none() => username = Some(parser.value()?),
            Long("domain") if other_arguments.is_none() => domain = Some(parser.value()?),
            Long("password") if other_arguments.is_none() => password = Some(parser.value()?),
            Long("") if other_arguments.is_none() => {
                other_arguments = Some(parser.values()?.collect())
            }
            Value(path) if process_path.is_none() => {
                process_path = Some(path.into());
            }
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(GlobalArguments {
        username: username.ok_or("Missing option username")?,
        domain: domain,
        password: password.ok_or("Missing option password")?,
        process_path: process_path.ok_or("Missing argument ProcessPath")?,
        process_arguments: other_arguments.unwrap_or(vec![]),
    })
}

unsafe fn start_interactive_client_process(args: GlobalArguments) -> anyhow::Result<()> {
    use windows::{core::*, Win32::Foundation::*, Win32::Security::*};

    let mut domain_argument = HSTRING::new();
    if let Some(domain_value) = args.domain {
        domain_argument = HSTRING::from(domain_value);
    }

    let mut user_access_token = HANDLE::default();
    LogonUserW(
        &HSTRING::from(args.username),
        &domain_argument,
        &HSTRING::from(args.password),
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &mut user_access_token,
    )
    .ok()?;

    println!("SUCCESS, got token {:?}", user_access_token);

    Ok(())
}
