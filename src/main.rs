use std::{
    alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout},
    ffi::{c_void, OsString},
    mem::{size_of, size_of_val},
    os::windows::prelude::OsStrExt,
    path::PathBuf,
    ptr::addr_of,
};

use anyhow::{anyhow, ensure, Context};
use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::Security::*,
    Win32::System::{
        Memory::{LocalAlloc, LPTR},
        StationsAndDesktops::*,
    },
    Win32::System::{
        RemoteDesktop::*,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
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

struct HeapWrapped<Type> {
    data: *mut Type,
    allocation_layout: Layout,
}

impl<Type> HeapWrapped<Type> {
    fn new(allocation_layout: Layout) -> anyhow::Result<Self> {
        ensure!(
            allocation_layout.size() > 0,
            "Failed to create valid layout"
        );

        // SAFETY; Allocation size is greater than 0
        let data = unsafe { alloc_zeroed(allocation_layout) } as *mut Type;
        if data.is_null() {
            handle_alloc_error(allocation_layout);
        }

        Ok(HeapWrapped {
            data,
            allocation_layout,
        })
    }
}

impl<Type> AsRef<Type> for HeapWrapped<Type> {
    fn as_ref(&self) -> &Type {
        // SAFETY; Constructor enforced following pointer details
        // - Size > 0
        // - Proper aligment
        // - Dereferenceable
        // SAFETY; Is the pointed to data a valid TYPE?
        unsafe { &*self.data }
    }
}

impl<Type> AsMut<Type> for HeapWrapped<Type> {
    fn as_mut(&mut self) -> &mut Type {
        // SAFETY; Constructor enforced following pointer details
        // - Size > 0
        // - Proper aligment
        // - Dereferenceable
        // SAFETY; Is the pointed to data a valid TYPE?
        unsafe { &mut *self.data }
    }
}

impl<Type> Drop for HeapWrapped<Type> {
    fn drop(&mut self) {
        // SAFETY; The pointed to buffer is valid, enforced in the constructor, and we're
        // using the same layout from the creation call.
        unsafe { dealloc(self.data.cast(), self.allocation_layout) }
    }
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
    Ok(())
}

// SAFETY; Return the TOKEN_USER struct because the SID deallocates when that struct goes out of scope.
fn get_current_user_token() -> anyhow::Result<impl AsRef<TOKEN_USER>> {
    let token_current_process = {
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        }
        token
    };

    // WARN; Idiomatic use of GetTokenInformation requires us to call the method twice.
    // The first time is to retrieve how many bytes we need to allocate for the requested data.
    // The second time to retrieve the actual data. This second call could still fail if the allocated size isn't large enough.
    let mut bytes_required = 0;
    unsafe {
        // WARN; We expect this method to return failure, so we consume the result and assert bytes_required below.
        let _ = GetTokenInformation(
            token_current_process,
            TokenUser,
            None,
            0,
            &mut bytes_required,
        );
    }

    ensure!(
        bytes_required > 0,
        "Unable to get the size of the token information"
    );

    // WARN; Dynamically allocate the required size because mem::zeroed() is not a general purpose idiomatic solution (and sets a bad example).
    // NOTE; Alignment is set to the platform pointer size because I have no better guess. This value is restricted by Layout requirements as well.
    let allocation_layout =
        Layout::from_size_align(bytes_required as _, size_of::<*const c_void>())?;
    let buffer = HeapWrapped::<TOKEN_USER>::new(allocation_layout)?;

    unsafe {
        GetTokenInformation(
            token_current_process,
            TokenUser,
            // SAFETY; buffer.data will be provided a valid TOKEN_USER struct
            Some(buffer.data.cast()),
            bytes_required,
            &mut bytes_required,
        )
        .ok()?;
    }

    Ok(buffer)
}

fn get_local_system_sid() -> anyhow::Result<PSID> {
    const SECURITY_LOCAL_SYSTEM_RID: u32 = 18;
    let mut sessionid_localsystem = PSID::default();
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
            &mut sessionid_localsystem,
        )
        .ok()?;
    }
    Ok(sessionid_localsystem)
}

unsafe fn precondition_account_localsystem() -> anyhow::Result<()> {
    let current_user_sid = get_current_user_token()?.as_ref().User.Sid;
    // TODO; Wrap allocated SID object into cleanup type.
    let system_sid = get_local_system_sid()?;
    let comparison = EqualSid(current_user_sid, system_sid)
        .ok()
        .map_err(|_| anyhow!("The process owner is not LOCAL_SYSTEM"));
    FreeSid(system_sid);

    return comparison;
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
