use std::{ffi::OsString, os::windows::prelude::OsStrExt, path::PathBuf};

use anyhow::Context;
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::System::Threading::CreateProcessW,
};

macro_rules! HELP {
    () => {
"\
Magix Hide

USAGE:
    {bin_name} [FLAGS] [OPTIONS] ProcessPath -- ProcessArgument1 ProcessArgument2 ProcessArgumentN

FLAGS:
    --help                          Prints help information and exits

OPTIONS:
    # None yet

ARGS:
    ProcessPath       PATH          The location of the process to execute
    --
    ProcessArgumentN  STRING        Arguments passed to the proces on start
"
    };
}

enum Instruction<PayloadType> {
    Continue(PayloadType),
    Terminate,
}

struct Arguments {
    process_path: PathBuf,
    process_arguments: Vec<OsString>,
}

fn main() -> anyhow::Result<()> {
    match parse_args().context("Failed to parse command line arguments")? {
        Instruction::Terminate => return Ok(()),
        Instruction::Continue(args) => unimplemented!(),
    }
}

fn parse_args() -> anyhow::Result<Instruction<Arguments>, lexopt::Error> {
    use lexopt::prelude::*;

    let mut process_path = None;
    let mut other_arguments = vec![];

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                let bin_name = parser.bin_name().unwrap_or("magix-hide.exe");
                println!(HELP!(), bin_name = bin_name);
                return Ok(Instruction::Terminate);
            }
            Value(argument) if process_path.is_none() => {
                process_path = Some(argument.into());
            }
            // TODO; Everything after -- should be copied as is.
            // StartProcess requires us to pass a single argument string, so we need to reconstruct
            // and this implies proper quoting! Hmm this is a shitty situation...
            Value(argument) => other_arguments.push(argument),
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(Instruction::Continue(Arguments {
        process_path: process_path.ok_or("Missing argument ProcessPath")?,
        process_arguments: other_arguments,
    }))
}

fn launch_process(args: Arguments) -> anyhow::Result<()> {
    let application_path_data = args
        .process_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();

    let mut application_arguments_data = { unimplemented!() };

    unsafe {
        CreateProcessW(
            PCWSTR::from_raw(application_path_data.as_mut_ptr()),
            lpcommandline,
            lpprocessattributes,
            lpthreadattributes,
            binherithandles,
            dwcreationflags,
            lpenvironment,
            lpcurrentdirectory,
            lpstartupinfo,
            lpprocessinformation,
        )
    };

    unimplemented!()
}
