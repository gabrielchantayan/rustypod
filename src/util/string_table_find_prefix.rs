//! string_table_find_prefix — original: `FUN_0807b3c8` @ 0x0807b3c8 (124 bytes).
//!
//! Raw ARM extent is 0x0807b3c8..0x0807b444: 116 instruction bytes followed
//! by the 4-byte table-base literal at 0x0807b444; the next real function
//! starts at 0x0807b45c. Five incoming plain `bl` calls were verified
//! (0x08099860, 0x080999e4, 0x08099a28, 0x080b5f0c, 0x080b607c), with no
//! incoming predicated `bl` calls. There is one outgoing plain `bl`, to
//! `strncmp` (0x0803105c), and no predicated calls.
//!
//! Scans all 74 pointers in the runtime-populated table at 0x0890dca4. It
//! skips a `strncmp` call when the candidate's first byte differs, otherwise
//! compares the candidate length supplied by the caller. Returns the first
//! matching slot, or 75 when no entry matches. Deliberate deviations: the
//! host-only table seam uses native-width pointers; a volatile `strncmp`
//! function pointer preserves the call boundary, generating `blx` rather
//! than the original direct `bl` instead of inlining the comparison.

use core::ptr;

const STRING_TABLE_BASE: *const *const u8 = 0x0890_dca4 as *const *const u8;
pub const STRING_TABLE_ENTRIES: usize = 0x4a;
pub const STRING_TABLE_NOT_FOUND: u32 = 0x4b;

#[cfg(not(target_os = "none"))]
static mut HOST_STRING_TABLE: [*const u8; STRING_TABLE_ENTRIES] = [ptr::null(); STRING_TABLE_ENTRIES];

#[inline(always)]
unsafe fn string_table() -> *const *const u8 {
    #[cfg(target_os = "none")]
    {
        STRING_TABLE_BASE
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of!(HOST_STRING_TABLE).cast::<*const u8>()
    }
}

/// Returns the first table entry that prefixes `candidate` for `candidate_len` bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_table_find_prefix(candidate: *const u8, candidate_len: usize) -> u32 {
    let candidate_first = ptr::read_volatile(candidate);
    let table = string_table();
    let compare = ptr::read_volatile(
        &(crate::libc::strncmp::strncmp as unsafe extern "C" fn(*const u8, *const u8, usize) -> i32),
    );

    for index in 0..STRING_TABLE_ENTRIES {
        let entry = ptr::read(table.add(index));
        if ptr::read_volatile(entry) == candidate_first && compare(entry, candidate, candidate_len) == 0 {
            return index as u32;
        }
    }

    STRING_TABLE_NOT_FOUND
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TABLE_LOCK: Mutex<()> = Mutex::new(());
    static EMPTY_ENTRY: [u8; 1] = [0];


    unsafe fn set_entry(index: usize, value: *const u8) {
        ptr::write(core::ptr::addr_of_mut!(HOST_STRING_TABLE).cast::<*const u8>().add(index), value);
    }

    unsafe fn clear_table() {
        for index in 0..STRING_TABLE_ENTRIES {
            set_entry(index, EMPTY_ENTRY.as_ptr());
        }
    }

    #[test]
    fn returns_first_prefix_match() {
        let _lock = TABLE_LOCK.lock();
        let alpha = b"alpha\0";
        let alpine = b"alpine\0";
        unsafe {
            clear_table();
            set_entry(3, alpha.as_ptr());
            set_entry(9, alpine.as_ptr());
            assert_eq!(string_table_find_prefix(b"alphabet\0".as_ptr(), 5), 3);
        }
    }

    #[test]
    fn checks_only_the_supplied_length() {
        let _lock = TABLE_LOCK.lock();
        let alpha = b"alpha\0";
        unsafe {
            clear_table();
            set_entry(12, alpha.as_ptr());
            assert_eq!(string_table_find_prefix(b"alps\0".as_ptr(), 3), 12);
            assert_eq!(string_table_find_prefix(b"alps\0".as_ptr(), 4), STRING_TABLE_NOT_FOUND);
        }
    }

    #[test]
    fn returns_not_found_when_first_byte_or_contents_do_not_match() {
        let _lock = TABLE_LOCK.lock();
        let alpha = b"alpha\0";
        unsafe {
            clear_table();
            set_entry(0, alpha.as_ptr());
            assert_eq!(string_table_find_prefix(b"beta\0".as_ptr(), 4), STRING_TABLE_NOT_FOUND);
            assert_eq!(string_table_find_prefix(b"altar\0".as_ptr(), 5), STRING_TABLE_NOT_FOUND);
        }
    }
}
