//! Finds a candidate record whose string matches a key-pair lookup result.
//!
//! `keyed_record_find_string_match` — original: `FUN_082a1df8` @ 0x082a1df8
//! (92 bytes, `0x082a1df8..0x082a1e54`; three plain `bl` instructions and no
//! predicated `bl` instructions, verified by decoding `osos.dec`).
//!
//! It first resolves `(key_a, key_b)` through the adjacent, unported
//! 0x082a1e54 key-pair table search. If that succeeds, it scans the owner's
//! 32-byte candidate records in `[owner + 0x2c, owner + 0x30)`. Each candidate
//! begins with a target-layout `StringObject`; its NULL-safe C string is
//! compared to the resolved entry's word at +0x10 with `utf8_strcmp_safe`.
//! The first equal candidate is returned, otherwise NULL.
//!
//! Deliberate deviations: the key-pair search remains an explicit firmware
//! boundary. On host builds candidate payloads are read as target-width words,
//! rather than through Rust's wider `StringObject` layout; ARM calls the
//! ported `string_object_c_str` directly.

#[cfg(target_os = "none")]
use crate::cxx::string_object::{string_object_c_str, StringObject};
use crate::cxx::string_object::utf8_strcmp_safe;

type KeyPairEntryFind = unsafe extern "C" fn(*mut u8, u32, u32) -> *mut u8;

unsafe extern "C" fn firmware_key_pair_entry_find(
    owner: *mut u8,
    key_a: u32,
    key_b: u32,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let find: KeyPairEntryFind = core::mem::transmute(0x082a_1e54usize);
        find(owner, key_a, key_b)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (owner, key_a, key_b);
        core::ptr::null_mut()
    }
}

static mut KEY_PAIR_ENTRY_FIND: KeyPairEntryFind = firmware_key_pair_entry_find;

#[inline(always)]
unsafe fn key_pair_entry_find() -> KeyPairEntryFind {
    core::ptr::read_volatile(core::ptr::addr_of!(KEY_PAIR_ENTRY_FIND))
}

#[inline(always)]
unsafe fn candidate_c_str(candidate: *const u8) -> *const u8 {
    #[cfg(target_os = "none")]
    {
        string_object_c_str(candidate.cast::<StringObject>())
    }
    #[cfg(not(target_os = "none"))]
    {
        candidate.add(4).cast::<u32>().read() as usize as *const u8
    }
}

/// # Safety
/// `owner` must be readable through +0x30. The key-pair search boundary must
/// return either NULL or an entry readable through +0x10; every candidate in
/// the target-width range must contain a StringObject at offset zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn keyed_record_find_string_match(
    owner: *mut u8,
    key_a: u32,
    key_b: u32,
) -> *mut u8 {
    let entry = key_pair_entry_find()(owner, key_a, key_b);
    if entry.is_null() {
        return core::ptr::null_mut();
    }

    let wanted = entry.add(0x10).cast::<u32>().read() as usize as *const u8;
    let mut candidate = owner.add(0x2c).cast::<u32>().read() as usize as *mut u8;
    let end = owner.add(0x30).cast::<u32>().read() as usize as *mut u8;
    while candidate != end {
        if utf8_strcmp_safe(wanted, candidate_c_str(candidate)) == 0 {
            return candidate;
        }
        candidate = candidate.add(0x20);
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::KEYED_RECORD_FIND_STRING_MATCH, 0x1000).map(|pointer| pointer as usize)
    });
    static mut ENTRY_RESULT: *mut u8 = ptr::null_mut();
    static mut OBSERVED_KEYS: (u32, u32) = (0, 0);

    unsafe extern "C" fn key_pair_entry_find_stub(
        _owner: *mut u8,
        key_a: u32,
        key_b: u32,
    ) -> *mut u8 {
        OBSERVED_KEYS = (key_a, key_b);
        ENTRY_RESULT
    }

    unsafe fn base() -> *mut u8 {
        SLAB.expect("fixture mapping was checked") as *mut u8
    }

    unsafe fn write_ptr(field: *mut u8, value: *const u8) {
        field.cast::<u32>().write(value as usize as u32);
    }

    unsafe fn reset() {
        base().write_bytes(0, 0x1000);
        ENTRY_RESULT = ptr::null_mut();
        OBSERVED_KEYS = (0, 0);
    }

    #[test]
    fn returns_null_without_scanning_when_key_pair_is_absent() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("cxx/keyed_record_find_string_match")); return; }
        unsafe {
            let old_find = KEY_PAIR_ENTRY_FIND;
            KEY_PAIR_ENTRY_FIND = key_pair_entry_find_stub;
            reset();
            write_ptr(base().add(0x2c), base().add(0x200));
            write_ptr(base().add(0x30), base().add(0x220));
            assert!(keyed_record_find_string_match(base(), 7, 9).is_null());
            assert_eq!(OBSERVED_KEYS, (7, 9));
            KEY_PAIR_ENTRY_FIND = old_find;
        }
    }

    #[test]
    fn skips_nonmatching_records_and_returns_first_utf8_match() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("cxx/keyed_record_find_string_match")); return; }
        unsafe {
            let old_find = KEY_PAIR_ENTRY_FIND;
            KEY_PAIR_ENTRY_FIND = key_pair_entry_find_stub;
            reset();
            let entry = base().add(0x100);
            let candidates = base().add(0x200);
            let wanted = base().add(0x380);
            wanted.copy_from_nonoverlapping(b"caf\xc3\xa9\0".as_ptr(), 6);
            let other = base().add(0x3a0);
            other.copy_from_nonoverlapping(b"coffee\0".as_ptr(), 7);
            write_ptr(entry.add(0x10), wanted);
            write_ptr(candidates.add(4), other);
            write_ptr(candidates.add(0x20 + 4), wanted);
            write_ptr(base().add(0x2c), candidates);
            write_ptr(base().add(0x30), candidates.add(0x40));
            ENTRY_RESULT = entry;
            assert_eq!(keyed_record_find_string_match(base(), 0x26, 3), candidates.add(0x20));
            assert_eq!(OBSERVED_KEYS, (0x26, 3));
            KEY_PAIR_ENTRY_FIND = old_find;
        }
    }

    #[test]
    fn treats_null_candidate_payload_as_an_empty_string() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("cxx/keyed_record_find_string_match")); return; }
        unsafe {
            let old_find = KEY_PAIR_ENTRY_FIND;
            KEY_PAIR_ENTRY_FIND = key_pair_entry_find_stub;
            reset();
            let entry = base().add(0x100);
            let candidate = base().add(0x200);
            write_ptr(entry.add(0x10), ptr::null());
            write_ptr(candidate.add(4), ptr::null());
            write_ptr(base().add(0x2c), candidate);
            write_ptr(base().add(0x30), candidate.add(0x20));
            ENTRY_RESULT = entry;
            assert_eq!(keyed_record_find_string_match(base(), 1, 2), candidate);
            KEY_PAIR_ENTRY_FIND = old_find;
        }
    }
}
