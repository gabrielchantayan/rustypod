//! Retain the referenced object selected by a two-kind tagged entry.
//!
//! Port: `crypto_tagged_reference_retain` — `FUN_0806fca4` @ `0x0806fca4`
//! (**76 bytes**). Raw ARM words at `0x0806fca4..0x0806fce8` end in
//! `pop {r12,pc}`; the next separately linked function starts at `0x0806fcf0`
//! with `push {r2-r6,lr}`, confirming the extent. Decoding every ARM B/BL
//! word in `osos.dec` finds **4 plain unconditional inbound `bl` call sites**
//! (`0x0806ffec`, `0x080703a8`, `0x08070488`, `0x08070610`) and no predicated
//! inbound BL forms. The body has one unconditional direct `bl`, to the
//! already-ported `crypto_add_lock` @ `0x08043828`, and no predicated BL.
//!
//! # Algorithm
//!
//! Entry kind 1 selects the signed reference count at `entry[1] + 0x10` and
//! OpenSSL lock type 3; kind 2 selects `entry[1] + 0x0c` and lock type 6.
//! The selected count is incremented through `CRYPTO_add_lock(count, 1, type,
//! NULL, 0)`. Other kinds return without reading `entry[1]`.
//!
//! # Deliberate deviations
//!
//! The target's four-byte object pointer is represented as a `u32` word and
//! widened only at dereference time, preserving target field offsets on
//! 64-bit host fixtures. The direct ARM branch is an ordinary Rust call to
//! the ported callee.

use crate::crypto::add_lock::crypto_add_lock;

/// Retain the object referenced by a kind-1 or kind-2 tagged entry.
///
/// # Safety
///
/// `entry` must be a readable, four-byte-aligned two-word target-layout
/// record. For kinds 1 and 2, `entry[1]` must be a valid four-byte-aligned
/// target address with a writable signed reference-count word at +0x10 or
/// +0x0c respectively. As in retailOS, there is no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crypto_tagged_reference_retain(entry: *mut u32) {
    let (reference_count_offset, lock_type) = match unsafe { entry.read() } {
        1 => (0x10, 3),
        2 => (0x0c, 6),
        _ => return,
    };
    let object = unsafe { entry.add(1).read() } as usize as *mut u8;
    let reference_count = unsafe { object.add(reference_count_offset).cast::<i32>() };
    unsafe { crypto_add_lock(reference_count, 1, lock_type, core::ptr::null(), 0) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const FIXTURE_LEN: usize = 0x1000;
    const ENTRY_OFFSET: usize = 0x100;
    const OBJECT_OFFSET: usize = 0x200;
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static FIXTURE: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        try_map_u32_slab(hints::CRYPTO_TAGGED_REFERENCE_RETAIN, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    fn fixture() -> Option<(*mut u32, *mut u32)> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            let entry = base.add(ENTRY_OFFSET).cast::<u32>();
            let object = base.add(OBJECT_OFFSET).cast::<u32>();
            entry.add(1).write(object as usize as u32);
            Some((entry, object))
        }
    }

    #[test]
    fn each_recognized_kind_increments_its_own_reference_count_word() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((entry, object)) = fixture() else {
            assert!(note_missing_u32_fixture("crypto/tagged_reference_retain"));
            return;
        };
        unsafe {
            entry.write(1);
            object.add(4).write(41);
            object.add(3).write(99);
            crypto_tagged_reference_retain(entry);
            assert_eq!(object.add(4).read(), 42);
            assert_eq!(object.add(3).read(), 99);

            entry.write(2);
            crypto_tagged_reference_retain(entry);
            assert_eq!(object.add(4).read(), 42);
            assert_eq!(object.add(3).read(), 100);
        }
    }

    #[test]
    fn unsupported_kind_does_not_read_the_object_pointer_or_modify_entry() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((entry, _)) = fixture() else {
            assert!(note_missing_u32_fixture("crypto/tagged_reference_retain"));
            return;
        };
        unsafe {
            entry.write(0);
            entry.add(1).write(0);
            crypto_tagged_reference_retain(entry);
            assert_eq!(entry.read(), 0);
            assert_eq!(entry.add(1).read(), 0);
        }
    }
}
