// SPDX-License-Identifier: Apache-2.0

use std::{fs::File, io, mem::size_of, os::windows::io::AsRawHandle as _};

use windows::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx},
};

fn identity(file: &File) -> io::Result<FILE_ID_INFO> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: the borrowed File keeps its handle valid for this synchronous call.
    // The output pointer names initialized, correctly aligned FILE_ID_INFO storage
    // whose exact size is passed to the matching information class. Windows does
    // not retain the pointer or take ownership of the handle.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            std::ptr::from_mut(&mut information).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(io::Error::other)?;
    Ok(information)
}

pub(super) fn same_file(left: &File, right: &File) -> io::Result<bool> {
    let left = identity(left)?;
    let right = identity(right)?;
    Ok(left.VolumeSerialNumber == right.VolumeSerialNumber
        && left.FileId.Identifier == right.FileId.Identifier)
}
