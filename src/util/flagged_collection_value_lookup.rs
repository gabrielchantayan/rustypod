//! Selects a collection lookup implementation from the owner's mode flag.
//!
//! `flagged_collection_value_lookup` — original: `FUN_0822b064` @
//! **0x0822b064** (**100 bytes**, `0x0822b064..0x0822b0c4`; the next real
//! function begins with `push {r4,lr}` at `0x0822b0c8`). Raw ARM establishes
//! three inbound plain `bl` callers and no predicated inbound `bl` forms. The
//! body itself contains no `bl`/`blx`: it tail-branches to one of two complete
//! lookup bodies.
//!
//! # Algorithm
//!
//! Test flag bit 0 at owner `+0x5f8`. When clear, tail-dispatch the virtual
//! collection lookup at `0x08208488` with owner `+0x330`; when set,
//! tail-dispatch the bounded collection lookup at `0x08214b10` with owner
//! `+0x38`. Both retail targets acquire and release their respective mutex
//! handoffs and return the first word of a non-NULL result, or zero.
//!
//! # Deliberate deviations
//!
//! The two separately entered lookup bodies are not independently ported.
//! Target builds call their verified retail addresses. Host builds use
//! native-width contexts and injectable dispatches, preserving the flag,
//! selected context, key, and result without pretending 64-bit pointers fit
//! the target's four-byte fields. Rust calls rather than tail-branches.

const RETAIL_VIRTUAL_COLLECTION_LOOKUP: usize = 0x0820_8488;
const RETAIL_BOUNDED_COLLECTION_LOOKUP: usize = 0x0821_4b10;

type CollectionLookup = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct FlaggedCollectionOwner {
    pub mode_flags: u8,
    pub _padding: [u8; 7],
    pub bounded_context: *mut u8,
    pub virtual_context: *mut u8,
}

#[cfg(not(target_os = "none"))]
pub struct FlaggedCollectionLookupOps {
    pub virtual_lookup: CollectionLookup,
    pub bounded_lookup: CollectionLookup,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_lookup(_context: *mut u8, _key: u32) -> u32 {
    panic!("flagged collection lookup dispatch was not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut FLAGGED_COLLECTION_LOOKUP_OPS: FlaggedCollectionLookupOps = FlaggedCollectionLookupOps {
    virtual_lookup: unavailable_lookup,
    bounded_lookup: unavailable_lookup,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch(owner: *mut u8, key: u32) -> u32 {
    let mode_flags = owner.add(0x5f8).read_volatile();
    let (context, lookup): (*mut u8, CollectionLookup) = if mode_flags & 1 == 0 {
        (owner.add(0x330), core::mem::transmute(RETAIL_VIRTUAL_COLLECTION_LOOKUP))
    } else {
        (owner.add(0x38), core::mem::transmute(RETAIL_BOUNDED_COLLECTION_LOOKUP))
    };
    lookup(context, key)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch(owner: *mut u8, key: u32) -> u32 {
    let owner = &mut *owner.cast::<FlaggedCollectionOwner>();
    if owner.mode_flags & 1 == 0 {
        (FLAGGED_COLLECTION_LOOKUP_OPS.virtual_lookup)(owner.virtual_context, key)
    } else {
        (FLAGGED_COLLECTION_LOOKUP_OPS.bounded_lookup)(owner.bounded_context, key)
    }
}

/// Looks up `key` through the collection selected by owner flag bit 0.
///
/// # Safety
///
/// On target, `owner` must address the retail owner object with valid
/// collection contexts at `+0x38` and `+0x330`. On host it must be a
/// [`FlaggedCollectionOwner`] and [`FLAGGED_COLLECTION_LOOKUP_OPS`] must be
/// installed before calling.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn flagged_collection_value_lookup(owner: *mut u8, key: u32) -> u32 {
    dispatch(owner, key)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    use core::ptr::addr_of_mut;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut VIRTUAL_CALL: (*mut u8, u32) = (core::ptr::null_mut(), 0);
    static mut BOUNDED_CALL: (*mut u8, u32) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn virtual_lookup(context: *mut u8, key: u32) -> u32 {
        VIRTUAL_CALL = (context, key);
        0x1020_3040
    }

    unsafe extern "C" fn bounded_lookup(context: *mut u8, key: u32) -> u32 {
        BOUNDED_CALL = (context, key);
        0x5060_7080
    }

    unsafe fn install_ops() {
        FLAGGED_COLLECTION_LOOKUP_OPS = FlaggedCollectionLookupOps { virtual_lookup, bounded_lookup };
        VIRTUAL_CALL = (core::ptr::null_mut(), 0);
        BOUNDED_CALL = (core::ptr::null_mut(), 0);
    }

    #[test]
    fn clear_flag_uses_virtual_context_and_returns_its_word() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut virtual_context = [0u8; 1];
        let mut bounded_context = [0u8; 1];
        let mut owner = FlaggedCollectionOwner {
            mode_flags: 0xfe,
            _padding: [0; 7],
            bounded_context: bounded_context.as_mut_ptr(),
            virtual_context: virtual_context.as_mut_ptr(),
        };
        unsafe {
            install_ops();
            assert_eq!(flagged_collection_value_lookup(addr_of_mut!(owner).cast(), 0x1234_5678), 0x1020_3040);
            assert_eq!(VIRTUAL_CALL, (virtual_context.as_mut_ptr(), 0x1234_5678));
            assert_eq!(BOUNDED_CALL, (core::ptr::null_mut(), 0));
        }
    }

    #[test]
    fn set_flag_uses_bounded_context_and_preserves_the_full_key() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut virtual_context = [0u8; 1];
        let mut bounded_context = [0u8; 1];
        let mut owner = FlaggedCollectionOwner {
            mode_flags: 1,
            _padding: [0; 7],
            bounded_context: bounded_context.as_mut_ptr(),
            virtual_context: virtual_context.as_mut_ptr(),
        };
        unsafe {
            install_ops();
            assert_eq!(flagged_collection_value_lookup(addr_of_mut!(owner).cast(), u32::MAX), 0x5060_7080);
            assert_eq!(BOUNDED_CALL, (bounded_context.as_mut_ptr(), u32::MAX));
            assert_eq!(VIRTUAL_CALL, (core::ptr::null_mut(), 0));
        }
    }
}
