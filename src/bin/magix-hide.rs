use std::i128::MAX;
use std::iter::once;
use std::path::Path;
use std::process::Command;
use std::ptr::null_mut;
use std::{ffi::OsString, os::windows::prelude::OsStrExt, path::PathBuf};

use anyhow::{anyhow, Context};
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::Environment::{CreateEnvironmentBlock, GetCommandLineW};
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
    NORMAL_PRIORITY_CLASS,
};
use windows::Win32::UI::Shell::PathQuoteSpacesW;
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::System::Threading::CreateProcessW,
};

macro_rules! HELP {
    () => {
"\
Magix Hide

USAGE:
    {bin_name} [FLAGS] [OPTIONS] -- ProcessPath ProcessArgument1 ProcessArgument2 ProcessArgumentN

FLAGS:
    --help                          Prints help information and exits

OPTIONS:
    # None yet

ARGS:
    --                              Argument splitter
    ProcessPath       PATH          The location of the process to execute
    ProcessArgumentN  STRING        Arguments passed to the proces on start
"
    };
}

enum Instruction<PayloadType> {
    Continue(PayloadType),
    Terminate,
}

struct Arguments {
    commandline: Vec<OsString>,
}

fn main() -> anyhow::Result<()> {
    match parse_args().context("Failure during command line arguments parsing")? {
        Instruction::Terminate => return Ok(()),
        Instruction::Continue(arguments) => {
            ensure_path_exists(arguments.commandline.first())?;
            launch_process(arguments)
        }
    }
}

fn parse_args() -> anyhow::Result<Instruction<Arguments>, lexopt::Error> {
    use lexopt::prelude::*;

    let mut commandline = Vec::new();

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                let bin_name = parser.bin_name().unwrap_or("magix-hide.exe");
                println!(HELP!(), bin_name = bin_name);
                return Ok(Instruction::Terminate);
            }
            // NOTE; Everything after -- should be copied as is.
            // We will reconstruct the commandline string from these parts and pass into StartProcess
            Value(argument) => commandline.push(argument),
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(Instruction::Continue(Arguments { commandline }))
}

fn ensure_path_exists(path: Option<&OsString>) -> anyhow::Result<()> {
    let path: PathBuf = path
        .ok_or(anyhow!("Missing an argument for the process to execute"))?
        .into();
    // Maybe not necessary
    let _ = path
        .try_exists()?
        .then_some(())
        .ok_or(anyhow!("The path to execute does not exist"));

    Ok(())
}

fn launch_process(args: Arguments) -> anyhow::Result<()> {
    const NULL: u16 = 0 as _;
    const SPACE: u16 = b' ' as _;

    let commandline = args
        .commandline
        .iter()
        .map(|item| {
            let mut wide_string = item.as_os_str().encode_wide().chain(Some(NULL));
            let mut buffer = [(); MAX_PATH as usize].map(|_| wide_string.next().unwrap_or(0));
            assert!(
                matches!(wide_string.next(), None),
                "Iterator didn't finish!"
            );

            unsafe {
                PathQuoteSpacesW(&mut buffer).ok()?;
            }

            Ok::<_, windows::core::Error>(buffer)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .fold(Vec::new(), |mut acc, component| {
            acc.extend(
                component
                    .into_iter()
                    .take_while(|value| *value != 0u16)
                    .chain(Some(SPACE)),
            );
            acc
        });

    println!("Command string: {:?}", commandline);

    let user_handle = null_mut();

    let environment_block = null_mut();
    unsafe { CreateEnvironmentBlock(&mut environment_block, htoken, binherit) }

    unsafe {
        CreateProcessW(
            PCWSTR::null(), // No module name (use command line)
            PWSTR::from_raw(commandline.as_mut_ptr()),
            None,  // Process handle not inheritable
            None,  // Thread handle not inheritable
            false, // Set handle inheritance to FALSE
            NORMAL_PRIORITY_CLASS
                | CREATE_NO_WINDOW
                | CREATE_NEW_PROCESS_GROUP
                | CREATE_UNICODE_ENVIRONMENT,
            lpenvironment,
            lpcurrentdirectory,
            lpstartupinfo,
            lpprocessinformation,
        )
    };

    unimplemented!()
}
