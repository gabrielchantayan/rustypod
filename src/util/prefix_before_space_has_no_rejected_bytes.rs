//! `prefix_before_space_has_no_rejected_bytes` — original: `FUN_08396dc4` @
//! `0x08396dc4` (**88 bytes**, `0x08396dc4..0x08396e1b`; the next real
//! function begins at `0x08396e1c` with `push {r1, r2, r3, r4, r5, r6, r7,
//! lr}`). Raw A32 decoding finds three plain unconditional inbound `bl` call
//! sites (`0x082e313c`, `0x082e35c8`, and `0x082e63b4`) and no predicated
//! forms. Its body makes one plain `bl` to the unported byte-list predicate
//! at `0x082b14e8`.
//!
//! Scans at most `len` bytes. A rejected byte before the first space rejects;
//! a space at index zero rejects, while a later space accepts immediately and
//! leaves the suffix unchecked. Exhausting a nonnegative length accepts.
//!
//! ## Deliberate deviations
//!
//! The byte-list predicate at `0x082b14e8` has no established name or Rust
//! port. Target builds call its verified retail address; host builds expose a
//! replaceable seam for fixtures.

use core::ptr;

/// ABI of the unported byte-list predicate at `0x082b14e8`.
pub type ByteListPredicate = unsafe extern "C" fn(byte: u32) -> u32;

#[cfg(target_os = "none")]
const BYTE_LIST_PREDICATE_ADDRESS: usize = 0x082b_14e8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_byte_is_rejected(byte: u32) -> u32 {
    let predicate: ByteListPredicate = core::mem::transmute(BYTE_LIST_PREDICATE_ADDRESS);
    predicate(byte)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_byte_is_rejected(_byte: u32) -> u32 {
    panic!("prefix validator requires byte-list predicate 0x082b14e8")
}

/// Active boundary for the unresolved retail byte-list predicate.
pub static mut PREFIX_BYTE_LIST_PREDICATE: ByteListPredicate = retail_byte_is_rejected;

#[inline(always)]
fn byte_list_predicate() -> ByteListPredicate {
    unsafe { ptr::read_volatile(ptr::addr_of!(PREFIX_BYTE_LIST_PREDICATE)) }
}

/// Returns one when the bounded prefix passes the retail byte-list predicate.
///
/// # Safety
///
/// `bytes` must be readable for `len` bytes when `len` is positive. The
/// target predicate at `0x082b14e8` must remain callable on firmware builds.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn prefix_before_space_has_no_rejected_bytes(bytes: *const u8, len: i32) -> u32 {
    let mut index = 0i32;
    while index < len {
        let byte = u32::from(bytes.add(index as usize).read_volatile());
        if byte == u32::from(b' ') {
            return u32::from(index != 0);
        }
        if byte_list_predicate()(byte) != 0 {
            return 0;
        }
        index = index.wrapping_add(1);
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut REJECTED: [u8; 256] = [0; 256];

    unsafe extern "C" fn fixture_byte_is_rejected(byte: u32) -> u32 {
        u32::from(REJECTED[byte as usize] != 0)
    }

    struct PredicateGuard(ByteListPredicate);

    impl Drop for PredicateGuard {
        fn drop(&mut self) {
            unsafe { PREFIX_BYTE_LIST_PREDICATE = self.0; }
        }
    }

    fn install_fixture() -> PredicateGuard {
        unsafe {
            REJECTED = [0; 256];
            let old = PREFIX_BYTE_LIST_PREDICATE;
            PREFIX_BYTE_LIST_PREDICATE = fixture_byte_is_rejected;
            PredicateGuard(old)
        }
    }

    #[test]
    fn accepts_empty_and_nonpositive_bounds_without_reading() {
        let _lock = SEAM_LOCK.lock();
        let _guard = install_fixture();
        let bytes = [0xff];
        unsafe {
            assert_eq!(prefix_before_space_has_no_rejected_bytes(bytes.as_ptr(), 0), 1);
            assert_eq!(prefix_before_space_has_no_rejected_bytes(bytes.as_ptr(), -1), 1);
        }
    }

    #[test]
    fn rejects_a_leading_space_but_accepts_later_space_without_scanning_suffix() {
        let _lock = SEAM_LOCK.lock();
        let _guard = install_fixture();
        unsafe { REJECTED[b'x' as usize] = 1; }
        unsafe {
            assert_eq!(prefix_before_space_has_no_rejected_bytes(b" x".as_ptr(), 2), 0);
            assert_eq!(prefix_before_space_has_no_rejected_bytes(b"ok x".as_ptr(), 4), 1);
        }
    }

    #[test]
    fn checks_each_byte_before_space_and_honors_the_bound() {
        let _lock = SEAM_LOCK.lock();
        let _guard = install_fixture();
        unsafe { REJECTED[b'x' as usize] = 1; }
        unsafe {
            assert_eq!(prefix_before_space_has_no_rejected_bytes(b"ax".as_ptr(), 2), 0);
            assert_eq!(prefix_before_space_has_no_rejected_bytes(b"ax".as_ptr(), 1), 1);
            assert_eq!(prefix_before_space_has_no_rejected_bytes(b"abc".as_ptr(), 3), 1);
        }
    }
}
