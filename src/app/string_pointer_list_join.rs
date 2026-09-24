//! Join a counted list of C strings into its preallocated destination.

/// A target-layout string pointer list. The +4 word is not read by this helper.
#[repr(C)]
pub struct StringPointerList {
    pub strings: *const *const u8,
    pub unused: u32,
    pub count: u32,
}

#[cfg(target_os = "none")]
const _: [u8; 0x0c] = [0; core::mem::size_of::<StringPointerList>()];
#[cfg(target_os = "none")]
const _: [u8; 0x8] = [0; core::mem::offset_of!(StringPointerList, count)];

/// `string_pointer_list_join` — original: `FUN_080879d0` @ `0x080879d0`.
///
/// True extent: 148 bytes (`0x080879d0..0x08087a64`), ending at the separate
/// `ata_data_transfer_status_ok` entry. Raw-image ARM decoding finds zero
/// outbound `bl` instructions and two inbound plain `bl` call sites
/// (`0x08098ba0`, `0x080a0264`); no predicated `bl` forms.
///
/// Clears `*out_len`, then, when `list` is non-null and nonempty, copies each
/// NUL-terminated string in order to the destination at `*list.strings`, puts
/// the low byte of `separator` between adjacent strings, terminates the result,
/// stores its byte length, and returns its destination. Otherwise it returns
/// null. Deliberate deviation: typed Rust fields express the three target words;
/// host pointer width changes their host offsets but not the target layout.
///
/// # Safety
///
/// `out_len` must be writable. A non-null, nonempty `list` must describe
/// `count` valid C-string pointers and a sufficiently large writable destination.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_pointer_list_join(
    list: *const StringPointerList,
    separator: u32,
    out_len: *mut u32,
) -> *mut u8 {
    unsafe { out_len.write(0); }
    if list.is_null() || unsafe { (*list).count } == 0 {
        return core::ptr::null_mut();
    }

    let strings = unsafe { (*list).strings };
    let destination = unsafe { strings.read() } as *mut u8;
    let count = unsafe { (*list).count } as usize;
    let mut written = 0usize;

    for index in 0..count {
        let mut source = unsafe { strings.add(index).read() };
        loop {
            let byte = unsafe { source.read_volatile() };
            if byte == 0 {
                break;
            }
            unsafe { destination.add(written).write_volatile(byte); }
            written += 1;
            source = unsafe { source.add(1) };
        }
        if index + 1 < count {
            unsafe { destination.add(written).write_volatile(separator as u8); }
            written += 1;
        }
    }

    unsafe {
        destination.add(written).write_volatile(0);
        out_len.write(written as u32);
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_empty_strings_and_truncates_separator_to_a_byte() {
        let empty = b"\0";
        let last = b"last\0";
        let mut destination = [0xa5u8; 32];
        destination[..6].copy_from_slice(b"first\0");
        let strings = [destination.as_mut_ptr() as *const u8, empty.as_ptr(), last.as_ptr()];
        let list = StringPointerList { strings: strings.as_ptr(), unused: 0, count: 3 };
        let mut len = u32::MAX;

        let result = unsafe { string_pointer_list_join(&list, 0x123, &mut len) };

        assert_eq!(result, destination.as_mut_ptr());
        assert_eq!(len, 11);
        assert_eq!(&destination[..12], b"first##last\0");
    }

    #[test]
    fn null_and_empty_lists_clear_length_and_return_null() {
        let mut len = u32::MAX;
        assert!(unsafe { string_pointer_list_join(core::ptr::null(), 0, &mut len) }.is_null());
        assert_eq!(len, 0);

        let list = StringPointerList { strings: core::ptr::null(), unused: 0, count: 0 };
        len = u32::MAX;
        assert!(unsafe { string_pointer_list_join(&list, 0, &mut len) }.is_null());
        assert_eq!(len, 0);
    }
}
