//! Runtime C-string name-list matcher — `FUN_082dad24` @ 0x082dad24 (144 bytes;
//! inbound plain `bl` at 0x082e4a18 and 0x082e4a94; no predicated inbound `bl`).
//!
//! The raw extent is 0x082dad24..0x082dadb4: the trailing literal at
//! 0x082dadb4 is the 0x08a6a0ec list address, and the following `mov r3,r1`
//! starts a distinct function. This leaf walks the null-terminated list of
//! C-string pointers. A candidate matches when every differing list byte can
//! become the candidate byte by adding 0x20, the list string ends, and only
//! ASCII spaces remain in the candidate. It returns one for a match and zero
//! after the null list terminator.
//!
//! The ARM body has no outbound plain or predicated `bl` instructions. The
//! firmware list resides at 0x08a6a0ec, outside the decrypted image body; host
//! tests replace that runtime pointer table. The host seam uses native-width
//! pointers deliberately, while firmware accesses the verified four-byte ARM
//! pointer fields.

use core::ptr;

#[cfg(target_os = "none")]
const RUNTIME_NAME_LIST: *const u32 = 0x08a6_a0ec as *const u32;

#[cfg(not(target_os = "none"))]
static mut HOST_RUNTIME_NAME_LIST: *const *const u8 = ptr::null();

#[inline(always)]
unsafe fn runtime_name_at(index: usize) -> *const u8 {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(RUNTIME_NAME_LIST.add(index)) as usize as *const u8
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(HOST_RUNTIME_NAME_LIST.add(index))
    }
}

/// Returns whether `candidate` matches a runtime list entry, ignoring trailing spaces.
///
/// # Safety
///
/// `candidate` and every non-NULL runtime list entry must be readable,
/// NUL-terminated C strings. The runtime list itself must end with a NULL pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cstr_matches_runtime_name_list(candidate: *const u8) -> u32 {
    let mut list_index = 0;
    loop {
        let entry = runtime_name_at(list_index);
        if entry.is_null() {
            return 0;
        }

        let mut byte_index = 0;
        let mut matches = true;
        loop {
            let entry_byte = entry.add(byte_index).read();
            let candidate_byte = candidate.add(byte_index).read();
            if entry_byte == 0 || candidate_byte == 0 {
                if entry_byte == 0 && matches {
                    while candidate.add(byte_index).read() == b' ' {
                        byte_index += 1;
                    }
                    if candidate.add(byte_index).read() == 0 {
                        return 1;
                    }
                }
                break;
            }
            if entry_byte != candidate_byte && entry_byte.wrapping_add(0x20) != candidate_byte {
                matches = false;
            }
            byte_index += 1;
        }
        list_index += 1;
    }
}

#[cfg(all(test, not(target_os = "none")))]
unsafe fn replace_runtime_name_list(list: *const *const u8) -> *const *const u8 {
    let previous = HOST_RUNTIME_NAME_LIST;
    HOST_RUNTIME_NAME_LIST = list;
    previous
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static RUNTIME_NAME_LIST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn with_list(list: &[*const u8], candidate: &[u8]) -> u32 {
        let previous = replace_runtime_name_list(list.as_ptr());
        let result = cstr_matches_runtime_name_list(candidate.as_ptr());
        replace_runtime_name_list(previous);
        result
    }

    #[test]
    fn matches_list_entries_and_trailing_spaces() {
        let list = [b"Device\0".as_ptr(), b"serial\0".as_ptr(), core::ptr::null()];
        let _guard = RUNTIME_NAME_LIST_LOCK.lock();
        assert_eq!(unsafe { with_list(&list, b"Device   \0") }, 1);
        assert_eq!(unsafe { with_list(&list, b"serial\0") }, 1);
    }

    #[test]
    fn accepts_only_lowercase_offset_differences() {
        let list = [b"Name\0".as_ptr(), core::ptr::null()];
        let _guard = RUNTIME_NAME_LIST_LOCK.lock();
        assert_eq!(unsafe { with_list(&list, b"name\0") }, 1);
        assert_eq!(unsafe { with_list(&list, b"NAME\0") }, 0);
        assert_eq!(unsafe { with_list(&list, b"N!me\0") }, 0);
    }

    #[test]
    fn rejects_prefixes_suffixes_and_an_empty_list() {
        let list = [b"name\0".as_ptr(), core::ptr::null()];
        let empty = [core::ptr::null()];
        let _guard = RUNTIME_NAME_LIST_LOCK.lock();
        assert_eq!(unsafe { with_list(&list, b"nam\0") }, 0);
        assert_eq!(unsafe { with_list(&list, b"name.more\0") }, 0);
        assert_eq!(unsafe { with_list(&empty, b"\0") }, 0);
    }
}
