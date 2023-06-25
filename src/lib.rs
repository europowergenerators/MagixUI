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
