//! Nested-object value accessor — retailOS `FUN_08070c40` at `0x08070c40`
//! (**12 bytes**).
//!
//! Raw ARM establishes the extent: `ldr r0,[r0]; ldr r0,[r0,#0xc]; bx lr`.
//! The separately linked sibling begins with `cmp r0,#0` at `0x08070c4c`, so
//! Ghidra's 12-byte extent is exact. Decoding every ARM B/BL-immediate word
//! in `osos.dec` finds **11** inbound sites, all unconditional plain `bl`; no
//! predicated form or direct tail `b` reaches this entry.
//!
//! Algorithm: follow the owner's 32-bit target pointer at +0x00, then return
//! the nested object's word at +0x0c. Neither load has a NULL guard. The
//! concrete owner and nested-object identities are unrecovered, so these
//! layout names describe only the observed relationship rather than claiming
//! a class identity.
//!
//! Deliberate deviations: none.

/// A wrapper whose first target word points at a [`NestedObject`].
///
/// `nested` remains a `u32` even in host tests: ARM target pointers occupy
/// four bytes, while host-width pointer fields would alter the second load's
/// layout.
#[repr(C)]
pub struct NestedObjectOwner {
    pub nested: u32,
}

/// The observed four-word prefix of the nested object.
#[repr(C)]
pub struct NestedObject {
    pub words_before_value: [u32; 3],
    pub value: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(NestedObjectOwner, nested)];
const _: [u8; 0x04] = [0; core::mem::size_of::<NestedObjectOwner>()];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(NestedObject, value)];

/// nested_object_value — retailOS `FUN_08070c40` at `0x08070c40` (12 bytes;
/// 11 direct plain-`bl` call sites, binary-verified).
///
/// Returns the word at +0x0c of the object named by `owner`'s +0x00 target
/// pointer.
///
/// # Safety
///
/// `owner` must be non-NULL and point to a readable [`NestedObjectOwner`].
/// Its `nested` target word must be nonzero and name a readable,
/// word-aligned [`NestedObject`]. The retailOS loads fault for invalid
/// pointers; this port deliberately retains that contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.nested_object_value")]
#[inline(never)]
pub unsafe extern "C" fn nested_object_value(owner: *const NestedObjectOwner) -> u32 {
    let nested_address = unsafe { (*owner).nested };
    let nested = nested_address as usize as *const NestedObject;
    unsafe { (*nested).value }
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
        try_map_u32_slab(hints::NESTED_OBJECT_VALUE, FIXTURE_LEN).map(|pointer| pointer as usize)
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
    fn returns_the_value_from_the_nested_object() {
        let _lock = lock();
        let Some(owner) = fixture() else {
            assert!(note_missing_u32_fixture("cxx::nested_object_value"));
            return;
        };
        let nested = unsafe { owner.add(FIRST_NESTED_OFFSET).cast::<NestedObject>() };

        unsafe {
            nested.write(NestedObject {
                words_before_value: [0x1111_1111, 0x2222_2222, 0x3333_3333],
                value: 0xdec0_adde,
            });
            owner.cast::<NestedObjectOwner>().write(NestedObjectOwner {
                nested: nested as usize as u32,
            });
        }

        assert_eq!(unsafe { nested_object_value(owner.cast()) }, 0xdec0_adde);
    }

    #[test]
    fn follows_owner_pointer_and_reads_exact_word_three() {
        let _lock = lock();
        let Some(owner) = fixture() else {
            assert!(note_missing_u32_fixture("cxx::nested_object_value"));
            return;
        };
        let first = unsafe { owner.add(FIRST_NESTED_OFFSET).cast::<NestedObject>() };
        let second = unsafe { owner.add(SECOND_NESTED_OFFSET).cast::<NestedObject>() };

        unsafe {
            first.write(NestedObject {
                words_before_value: [0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc],
                value: 0x1111_1111,
            });
            second.write(NestedObject {
                words_before_value: [0xdddd_dddd, 0xeeee_eeee, 0xffff_ffff],
                value: 0x2222_2222,
            });
            owner.cast::<NestedObjectOwner>().write(NestedObjectOwner {
                nested: first as usize as u32,
            });
        }
        assert_eq!(unsafe { nested_object_value(owner.cast()) }, 0x1111_1111);

        unsafe { (*owner.cast::<NestedObjectOwner>()).nested = second as usize as u32 };
        assert_eq!(unsafe { nested_object_value(owner.cast()) }, 0x2222_2222);
    }
}
