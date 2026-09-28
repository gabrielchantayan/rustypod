//! NUL-terminated SQLite hash lookup wrapper.
//!
//! - `hash_find_cstr` — original: `FUN_08393ae8` @ **0x08393ae8**
//!   (40 bytes, 0x08393ae8..0x08393b10; **1 plain body `bl`, 0 predicated
//!   body `bl`; 2 plain inbound `bl` sites, 0 predicated inbound sites**).
//!
//! Loads the C string at `context + 0x04`, measures it with the unguarded
//! retailOS `strlen`, adds one for its NUL terminator, then tail-calls
//! `sqlite3HashFind` on the `Hash` embedded at `*(context + 0x20) + 0x04`.
//! The direct target is the existing [`super::hash_find::hash_find`] port.
//! Deliberate deviation: Rust calls that target rather than preserving the
//! ARM tail branch; the return value and arguments are unchanged.

use super::hash_clear::Hash;
use super::hash_find::hash_find;
use crate::libc::strlen::strlen;

const WORD: usize = core::mem::size_of::<usize>();

#[inline(always)]
const fn target_offset(offset: usize) -> usize {
    offset / 4 * WORD
}

#[inline(always)]
unsafe fn hash_find_cstr_with(
    context: *const u8,
    lookup: unsafe extern "C" fn(*const Hash, *const u8, i32) -> *mut u8,
) -> *mut u8 {
    let key = context.add(target_offset(0x04)).cast::<*const u8>().read();
    let owner = context.add(target_offset(0x20)).cast::<*const u8>().read();
    lookup(
        owner.add(target_offset(0x04)).cast::<Hash>(),
        key,
        strlen(key).wrapping_add(1) as i32,
    )
}

/// Looks up the NUL-terminated key embedded in `context`'s SQLite hash owner.
///
/// # Safety
/// `context` must have valid target-word fields at +0x04 and +0x20. Its key
/// must be NUL-terminated and its owner must contain a valid [`Hash`] at +0x04.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_find_cstr(context: *const u8) -> *mut u8 {
    hash_find_cstr_with(context, hash_find)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    static mut CALL: Option<(*const Hash, *const u8, i32)> = None;

    unsafe extern "C" fn recording_lookup(hash: *const Hash, key: *const u8, key_len: i32) -> *mut u8 {
        *core::ptr::addr_of_mut!(CALL) = Some((hash, key, key_len));
        0xfeed_beefusize as *mut u8
    }

    #[repr(C)]
    struct HashOwner {
        _header: usize,
        hash: Hash,
    }

    #[test]
    fn forwards_first_nul_length_including_terminator_at_target_word_offsets() {
        let key = b"master\0ignored\0";
        let owner: HashOwner = unsafe { core::mem::zeroed() };
        let mut context = [0usize; 9];
        context[1] = key.as_ptr() as usize;
        context[8] = (&owner as *const HashOwner).cast::<u8>() as usize;
        unsafe {
            *core::ptr::addr_of_mut!(CALL) = None;
            let result = hash_find_cstr_with(context.as_ptr().cast(), recording_lookup);
            assert_eq!(result, 0xfeed_beefusize as *mut u8);
            assert_eq!(
                *core::ptr::addr_of!(CALL),
                Some((&owner.hash as *const Hash, key.as_ptr(), 7)),
                "the key is at +0x04, owner at +0x20, and nKey includes only the first NUL"
            );
        }
    }

    #[test]
    fn empty_key_forwards_the_terminator_as_one_byte_key() {
        let key = b"\0";
        let owner: HashOwner = unsafe { core::mem::zeroed() };
        let mut context = [0usize; 9];
        context[1] = key.as_ptr() as usize;
        context[8] = (&owner as *const HashOwner).cast::<u8>() as usize;
        unsafe {
            let _ = hash_find_cstr_with(context.as_ptr().cast(), recording_lookup);
            assert_eq!((*core::ptr::addr_of!(CALL)).unwrap().2, 1);
        }
    }
}
