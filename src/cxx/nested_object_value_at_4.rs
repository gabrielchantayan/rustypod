//! Nested-object value accessor — retailOS `FUN_08070d5c` at `0x08070d5c`
//! (**12 bytes**).
//!
//! Raw ARM establishes the extent: `ldr r0,[r0]; ldr r0,[r0,#4]; bx lr`.
//! The separately linked sibling begins with `ldr r0,[r0]` at `0x08070d68`,
//! so Ghidra's 12-byte extent is exact. Decoding every ARM B/BL-immediate word
//! in `osos.dec` finds **5** inbound sites, all unconditional plain `bl`; no
//! predicated form or direct tail `b` reaches this entry.
//!
//! Algorithm: follow the owner's 32-bit target pointer at +0x00, then return
//! the nested object's word at +0x04. Neither load has a NULL guard. The
//! concrete owner and nested-object identities are unrecovered, so these
//! layout names describe only the observed relationship rather than claiming
//! a class identity.
//!
//! Deliberate deviations: none.

use super::nested_object_value::NestedObjectOwner;

/// Nested-object word selected by the second retailOS load.
const NESTED_VALUE_WORD: usize = 1;

/// nested_object_value_at_4 — retailOS `FUN_08070d5c` at `0x08070d5c` (12
/// bytes; 5 direct plain-`bl` call sites, binary-verified).
///
/// Returns the word at +0x04 of the object named by `owner`'s +0x00 target
/// pointer.
///
/// # Safety
///
/// `owner` must be non-NULL and point to a readable [`NestedObjectOwner`].
/// Its `nested` target word must be nonzero and name storage valid for an
/// aligned `u32` read at word 1. The retailOS loads fault for invalid pointers;
/// this port deliberately retains that contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.nested_object_value_at_4")]
#[inline(never)]
pub unsafe extern "C" fn nested_object_value_at_4(owner: *const NestedObjectOwner) -> u32 {
    let nested_address = unsafe { (*owner).nested };
    let nested = nested_address as usize as *const u32;
    unsafe { *nested.add(NESTED_VALUE_WORD) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const FIRST_NESTED_OFFSET: usize = 0x100;
    const SECOND_NESTED_OFFSET: usize = 0x200;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::NESTED_OBJECT_VALUE_AT_4, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<*mut u8> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe { core::ptr::write_bytes(base, 0, FIXTURE_LEN) };
        Some(base)
    }

    fn lock() -> MutexGuard<'static, ()> {
        match FIXTURE_LOCK.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn returns_the_second_nested_word() {
        let _lock = lock();
        let Some(owner) = fixture() else {
            assert!(note_missing_u32_fixture("cxx::nested_object_value_at_4"));
            return;
        };
        let nested = unsafe { owner.add(FIRST_NESTED_OFFSET).cast::<u32>() };

        unsafe {
            nested.write(0x1111_1111);
            nested.add(1).write(0xdec0_adde);
            nested.add(2).write(0x3333_3333);
            owner.cast::<NestedObjectOwner>().write(NestedObjectOwner {
                nested: nested as usize as u32,
            });
        }

        assert_eq!(unsafe { nested_object_value_at_4(owner.cast()) }, 0xdec0_adde);
    }

    #[test]
    fn follows_a_changed_owner_pointer() {
        let _lock = lock();
        let Some(owner) = fixture() else {
            assert!(note_missing_u32_fixture("cxx::nested_object_value_at_4"));
            return;
        };
        let first = unsafe { owner.add(FIRST_NESTED_OFFSET).cast::<u32>() };
        let second = unsafe { owner.add(SECOND_NESTED_OFFSET).cast::<u32>() };

        unsafe {
            first.write(0xaaaa_aaaa);
            first.add(1).write(0x1111_1111);
            second.write(0xbbbb_bbbb);
            second.add(1).write(0x2222_2222);
            owner.cast::<NestedObjectOwner>().write(NestedObjectOwner {
                nested: first as usize as u32,
            });
        }
        assert_eq!(unsafe { nested_object_value_at_4(owner.cast()) }, 0x1111_1111);

        unsafe { (*owner.cast::<NestedObjectOwner>()).nested = second as usize as u32 };
        assert_eq!(unsafe { nested_object_value_at_4(owner.cast()) }, 0x2222_2222);
    }
}
