use std::{
    ffi::OsString, mem::size_of_val, os::windows::prelude::OsStrExt, path::PathBuf, ptr::addr_of,
};

use anyhow::{anyhow, Context};
use windows::{
    core::*, Win32::Foundation::*, Win32::Security::*, Win32::System::RemoteDesktop::*,
    Win32::System::StationsAndDesktops::*,
};

macro_rules! HELP {
    () => {
"\
MagixUI

USAGE:
    {bin_name} [FLAGS] [OPTIONS] ProcessPath -- ProcessArgument1 ProcessArgument2 ProcessArgumentN

FLAGS:
    --help                          Prints help information

OPTIONS:
    --username        STRING        Start process as this user
    --domain          STRING        Specifies the domain against which username must be resolved
    --password        STRING        Use this password to logon the provided user
    --interactive     -             Start the process so it interacts with the console desktop session

ARGS:
    ProcessPath       PATH          The location of the process to execute
    --
    ProcessArgumentN  STRING        Arguments passed to the proces on start
"
    };
}

enum Commands {
    Launch,
    SlaveForDACLPermissions,
}

struct GlobalArguments {
    command: Commands,
    username: OsString,
    domain: Option<OsString>,
    password: OsString,
    process_path: PathBuf,
    process_arguments: Vec<OsString>,
    //
    interactive: bool,
}

fn main() -> anyhow::Result<()> {
    let args = parse_args().context("Failed to parse command line arguments")?;
    match args.command {
        Commands::Launch => unsafe { entrypoint_launch(&args) },
        Commands::SlaveForDACLPermissions => unsafe { entrypoint_slave_dacl(&args) },
    }
}

fn parse_args() -> anyhow::Result<GlobalArguments, lexopt::Error> {
    use lexopt::prelude::*;

    let mut command = None;
    let mut username = None;
    let mut domain = None;
    let mut password = None;
    let mut interactive = false;
    let mut process_path = None;
    let mut other_arguments = vec![];

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                let bin_name = parser.bin_name().unwrap_or("MagixUI.exe");
                println!(HELP!(), bin_name = bin_name);
                std::process::exit(0);
            }
            Long("username") => username = Some(parser.value()?),
            Long("domain") => domain = Some(parser.value()?),
            Long("password") => password = Some(parser.value()?),
            Short('i') | Long("interactive") => interactive = true,
            Value(argument) if command.is_none() => {
                if OsString::from("SLAVE") == argument {
                    command = Some(Commands::SlaveForDACLPermissions);
                } else {
                    command = Some(Commands::Launch);
                    process_path = Some(argument.into());
                }
            }
            Value(argument) if command.is_some() => other_arguments.push(argument),
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(GlobalArguments {
        command: command.ok_or("Couldn't resolve the intention for this process")?,
        username: username.ok_or("Missing option username")?,
        domain: domain,
        password: password.ok_or("Missing option password")?,
        interactive: interactive,
        process_path: process_path.ok_or("Missing argument ProcessPath")?,
        process_arguments: other_arguments,
    })
}

unsafe fn entrypoint_slave_dacl(args: &GlobalArguments) -> anyhow::Result<()> {
    todo!()
}

unsafe fn entrypoint_launch(args: &GlobalArguments) -> anyhow::Result<()> {
    precondition_account_localsystem()?;
    todo!()
}

unsafe fn precondition_account_localsystem() -> anyhow::Result<()> {
    let sid_current_user = { PSID::default() };

    let sid_localsystem = {
        let mut sessionid_localsystem = PSID::default();
        AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut sessionid_localsystem,
        )
        .ok()?;
        sessionid_localsystem
    };

    EqualSid(sid_current_user, sid_localsystem)
        .ok()
        .map_err(|_| anyhow!("The process owner is not LOCAL_SYSTEM"))
}

unsafe fn start_interactive_client_process(args: &GlobalArguments) -> anyhow::Result<()> {
    let username = args
        .username
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // TODO; Document that non-provided domain requires username to include domain part. For local users, provide '.' as domain.
    let domain = args.domain.as_ref().map(|domain_value| {
        domain_value
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>()
    });
    let password = args
        .password
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();

    let mut token_target_user = HANDLE::default();
    LogonUserW(
        PCWSTR::from_raw(username.as_ptr()),
        domain
            // SAFETY; Reference to stack variable required! Otherwise we'd drop our vector at the end of the first map function scope!
            .as_ref()
            .map(|data| PCWSTR::from_raw(data.as_ptr()))
            .unwrap_or(PCWSTR::null()),
        PCWSTR::from_raw(password.as_ptr()),
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &mut token_target_user,
    )
    .ok()?;

    let id_session_console = WTSGetActiveConsoleSessionId();
    SetTokenInformation(
        token_target_user,
        TokenSessionId,
        addr_of!(id_session_console) as _,
        size_of_val(&id_session_console) as _,
    )
    .ok()?;

    // NOTE; The caller's station is the station of the current session.
    // NOTE; The interactive station is targetted in the interactive session.

    let handle_caller_station = GetProcessWindowStation()?;
    let name_interactive_station = w!("winsta0");
    // NOTE; DACL = Discretionary Access Control List
    let access_read_write = DESKTOP_READ_CONTROL.0 | DESKTOP_WRITE_DAC.0;
    let handle_interactive_station =
        OpenWindowStationW(name_interactive_station, false, access_read_write)?;

    SetProcessWindowStation(handle_interactive_station).ok()?;

    Ok(())
}
