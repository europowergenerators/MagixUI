// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout},
    ffi::c_void,
    mem::size_of,
    ptr::addr_of_mut,
};

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{
        GetTokenInformation, TokenIntegrityLevel, TokenStatistics, TokenUser, TOKEN_ALL_ACCESS,
        TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_STATISTICS, TOKEN_USER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken, OpenThreadToken},
};

pub trait TokenClass {
    fn class() -> TOKEN_INFORMATION_CLASS;
}

impl TokenClass for TOKEN_MANDATORY_LABEL {
    fn class() -> TOKEN_INFORMATION_CLASS {
        TokenIntegrityLevel
    }
}

impl TokenClass for TOKEN_STATISTICS {
    fn class() -> TOKEN_INFORMATION_CLASS {
        TokenStatistics
    }
}

impl TokenClass for TOKEN_USER {
    fn class() -> TOKEN_INFORMATION_CLASS {
        TokenUser
    }
}

pub struct TokenInformation<T> {
    token_info: *mut T,
    layout: Layout,
}

impl<T: TokenClass> TokenInformation<T> {
    pub fn new(mut token: Token) -> anyhow::Result<Self> {
        let token_handle = token.get();
        // Retrieve the size of the struct.
        let mut size: u32 = 0;
        // Safe because size is valid, and TokenInformation is optional and allowed to be null.
        let token_information_result = unsafe {
            // The idiomatic usage of GetTokenInformation() requires two calls
            // to the function: the first to get the length of the data that the
            // function would return, and the second to fetch the data.
            GetTokenInformation(
                /* TokenHandle= */ token_handle,
                /* TokenInformationClass= */ T::class(),
                /* TokenInformation= */ None,
                /* TokenInformationLength= */ 0,
                /* ReturnLength= */ addr_of_mut!(size),
            )
            .ok()
        };

        if let Err(win32_error) = &token_information_result {
            match win32_error.code() {
                INSUFFICIENT_BUFFER => {
                    // Despite returning failure, the function will fill in the
                    // expected buffer length into the ReturnLength parameter.
                    // It may fail in other ways (e.g. if an invalid TokenHandle
                    // is provided), so we check that we receive the expected
                    // error code before assuming that we received a valid
                    // ReturnLength. In this case, we can ignore the error.
                }
                _ => token_information_result?,
            };
        }

        // size must be > 0. 0-sized layouts break alloc()'s assumptions.
        assert!(size > 0, "Unable to get size of token information");

        // Since we don't statically know the full size of the struct, we
        // allocate memory for it based on the previous call, aligned to pointer
        // size.
        let layout = Layout::from_size_align(size as usize, size_of::<*const c_void>())
            .expect("Failed to create layout");
        assert!(layout.size() > 0, "Failed to create valid layout");
        // Safe as we assert that layout's size is non-zero.
        let token_info = unsafe { alloc_zeroed(layout) } as *mut T;
        if token_info.is_null() {
            handle_alloc_error(layout);
        }

        let token_info = TokenInformation::<T> { token_info, layout };

        // Safe because token_user and size are valid.
        unsafe {
            GetTokenInformation(
                /* TokenHandle= */ token_handle,
                /* TokenInformationClass= */ T::class(),
                /* TokenInformation= */ Some(addr_of_mut!(token_info.token_info).cast()),
                /* TokenInformationLength= */ size,
                /* ReturnLength= */ addr_of_mut!(size),
            )
            .ok()?;
        }

        Ok(token_info)
    }
}

impl<T> AsRef<T> for TokenInformation<T> {
    fn as_ref(&self) -> &T {
        // Safe because the underlying pointer is guaranteed to be properly
        // aligned, dereferenceable, and point to a valid T. The underlying
        // value will not be modified through the pointer and can only be
        // accessed through these returned references.
        unsafe { &*self.token_info }
    }
}

impl<T> AsMut<T> for TokenInformation<T> {
    fn as_mut(&mut self) -> &mut T {
        // Safe because the underlying pointer is guaranteed to be properly
        // aligned, dereferenceable, and point to a valid T. The underlying
        // value will not be modified through the pointer and can only be
        // accessed through these returned references.
        unsafe { &mut *self.token_info }
    }
}

impl<T> Drop for TokenInformation<T> {
    fn drop(&mut self) {
        // Safe because we ensure the pointer is valid in the constructor, and
        // we are using the same layout struct as during the allocation.
        unsafe { dealloc(self.token_info as *mut u8, self.layout) }
    }
}

pub struct Token {
    token: HANDLE,
}

impl Token {
    /// Open the current process's token.
    pub fn new_for_process() -> anyhow::Result<Self> {
        // Safe because GetCurrentProcess is an alias for -1.
        Self::from_process(unsafe { GetCurrentProcess() })
    }

    /// Open the token of a process.
    pub fn from_process(proc_handle: HANDLE) -> anyhow::Result<Self> {
        let mut token: HANDLE = HANDLE::default();

        // Safe because token is valid.
        unsafe {
            OpenProcessToken(
                /* ProcessHandle= */ proc_handle,
                /* DesiredAccess= */ TOKEN_ALL_ACCESS,
                /* TokenHandle= */ addr_of_mut!(token),
            )
            .ok()?;
        }
        Ok(Token { token })
    }

    /// Open the token of a thread.
    pub fn from_thread(thread_handle: HANDLE) -> anyhow::Result<Self> {
        let mut token: HANDLE = HANDLE::default();

        // Safe because token is valid. We use OpenAsSelf to ensure the token access is measured
        // using the caller's non-impersonated identity.
        unsafe {
            OpenThreadToken(
                thread_handle,
                TOKEN_ALL_ACCESS,
                /*OpenAsSelf=*/ true,
                addr_of_mut!(token),
            )
            .ok()?;
        }
        Ok(Token { token })
    }

    fn get(&mut self) -> HANDLE {
        self.token
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // Safe as token is valid, but the call should be safe regardless.
        unsafe {
            CloseHandle(self.token);
        }
    }
}
