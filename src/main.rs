use std::{
    alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout},
    ffi::{c_void, OsString},
    mem::{size_of, size_of_val},
    os::windows::prelude::OsStrExt,
    path::PathBuf,
    ptr::{addr_of, addr_of_mut},
};

use anyhow::{anyhow, ensure, Context};
use log::trace;
use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::Security::*,
    Win32::{
        System::{
            Memory::{LocalAlloc, LPTR},
            StationsAndDesktops::*,
        },
        UI::Shell::{SHGetKnownFolderPath, KF_FLAG_CREATE},
    },
    Win32::{
        System::{
            RemoteDesktop::*,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::Shell::{LoadUserProfileW, PROFILEINFOW},
    },
};

mod google_crossvm;
use google_crossvm::*;

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

fn entrypoint_launch(args: &GlobalArguments) -> anyhow::Result<()> {
    trace!("Check required access permissions");
    let process_access_token = Token::new_for_process()?;
    let process_token_information = TokenInformation::<TOKEN_USER>::new(process_access_token)?;
    // TODO; Loosen this requirement and try to elevate into the required permission
    precondition_account_localsystem(&process_token_information.as_ref().User.Sid)?;

    let mut logon_access_token = logon_target_user(args)?;

    // TODO; Fail if the target user has a roaming profile!

    trace!("Load the user profile data");
    let mut profile_info = PROFILEINFOW::default();
    profile_info.dwSize = size_of::<PROFILEINFOW>() as u32;
    profile_info.lpUserName = {
        let username = args
            .username
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>()
            .as_mut_ptr();
        PWSTR::from_raw(username)
    };
    unsafe {
        LoadUserProfileW(
            unsafe { logon_access_token.get().clone() },
            addr_of_mut!(profile_info),
        )
        .ok()?;
    }

    trace!("Resolve the path for temporary storage");
    let guid_localappdatalow = GUID::from("A520A1A4-1780-4FF6-BD18-167343C5AF16");
    let path_localappdatalow = unsafe {
        SHGetKnownFolderPath(addr_of!(guid_localappdatalow), KF_FLAG_CREATE, unsafe {
            logon_access_token.get().clone()
        })?
    };



    // let access_token = get_target_user_accesstoken(args)?;
    // let appdata_known_folder: GUID = "F1B32785-6FBA-4FCF-9D55-7B8E7F157091".into();
    // let Token::Handle(access_token) = access_token else { unreachable!(); };
    // unsafe {
    //     let appdata_folder_path =
    //         SHGetKnownFolderPath(addr_of!(appdata_known_folder), KF_FLAG_CREATE, access_token)?;
    // }

    Ok(())
}

fn precondition_account_localsystem(current_user_sid: &PSID) -> anyhow::Result<()> {
    // TODO; Wrap allocated SID object into cleanup type.
    let system_sid = {
        const SECURITY_LOCAL_SYSTEM_RID: u32 = 18;
        let mut identifier = PSID::default();
        unsafe {
            AllocateAndInitializeSid(
                &SECURITY_NT_AUTHORITY,
                1,
                SECURITY_LOCAL_SYSTEM_RID,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut identifier,
            )
            .ok()?;
        }
        identifier
    };
    let comparison = unsafe {
        EqualSid(current_user_sid.clone(), system_sid)
            .ok()
            .map_err(|_| anyhow!("The process owner is not LOCAL_SYSTEM"))
    };
    unsafe { _ = FreeSid(system_sid) };

    return comparison;
}

fn logon_target_user(args: &GlobalArguments) -> anyhow::Result<Token> {
    let username = args
        .username
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>()
        .as_ptr();
    // TODO; Document that non-provided domain requires username to include domain part. For local users, provide '.' as domain.
    let domain = args.domain.as_ref().map(|domain_value| {
        domain_value
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>()
    });
    let password = args
        .password
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();

    let mut access_token = HANDLE::default();
    unsafe {
        LogonUserW(
            PCWSTR::from_raw(username),
            domain
                // SAFETY; Reference to stack variable required! Otherwise we'd drop our vector at the end of the first map function scope!
                .as_ref()
                .map(|data| PCWSTR::from_raw(data.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            PCWSTR::from_raw(password.as_ptr()),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut access_token,
        )
        .ok()?
    };
    return unsafe { Token::new_from_raw(access_token) };
}

unsafe fn start_interactive_client_process(args: &GlobalArguments) -> anyhow::Result<()> {
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
