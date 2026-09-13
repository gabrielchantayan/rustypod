//! `typed_handler_registry_lookup` — original: `FUN_082a7280` @ **0x082a7280**
//! (72 bytes, `0x082a7280..0x082a72c8`).
//!
//! Loads the first word of `type_id` as an index into the registry's optional
//! handler table. A nonzero in-range entry returns directly; an out-of-range
//! index or a zero table entry delegates all five ABI arguments unchanged to
//! the slow registry lookup at `0x082a72c8`.
//!
//! **Six direct `bl` call sites, all unconditional and no predicated forms**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`:
//! `0x083b5484`, `0x083b6ce4`, `0x083e7954`, `0x083eaaf8`, `0x083eab20`, and
//! `0x083eab48`.
//!
//! Deliberate deviation: `FUN_082a72c8` remains unported. Target builds call
//! its fixed retailOS address; host tests install a volatile seam.

#[cfg(test)]
extern crate std;

#[cfg(not(target_os = "none"))]
use core::ptr;

/// Firmware load address of the unported slow registry lookup.
pub const TYPED_HANDLER_REGISTRY_SLOW_LOOKUP_ADDRESS: usize = 0x082a_72c8;

/// ABI shared by the fast lookup and its unported slow fallback.
pub type TypedHandlerRegistryLookup = unsafe extern "C" fn(
    registry: *mut *mut u8,
    type_id: *const u32,
    direction: u32,
    flags: u32,
    default_entry: usize,
) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn typed_handler_registry_slow_lookup(
    registry: *mut *mut u8,
    type_id: *const u32,
    direction: u32,
    flags: u32,
    default_entry: usize,
) -> *mut u8 {
    let lookup: TypedHandlerRegistryLookup = core::mem::transmute(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP_ADDRESS);
    lookup(registry, type_id, direction, flags, default_entry)
}

#[cfg(not(target_os = "none"))]
pub(crate) unsafe extern "C" fn missing_typed_handler_registry_slow_lookup(
    _registry: *mut *mut u8,
    _type_id: *const u32,
    _direction: u32,
    _flags: u32,
    _default_entry: usize,
) -> *mut u8 {
    panic!("install typed-handler registry slow-lookup host seam before calling this port")
}

/// Active host boundary for the unported slow registry lookup.
#[cfg(not(target_os = "none"))]
pub static mut TYPED_HANDLER_REGISTRY_SLOW_LOOKUP: TypedHandlerRegistryLookup = missing_typed_handler_registry_slow_lookup;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn typed_handler_registry_slow_lookup(
    registry: *mut *mut u8,
    type_id: *const u32,
    direction: u32,
    flags: u32,
    default_entry: usize,
) -> *mut u8 {
    let lookup = ptr::read_volatile(ptr::addr_of!(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP));
    lookup(registry, type_id, direction, flags, default_entry)
}

/// Finds a typed handler in a registry's direct table or delegates to its
/// unported slow lookup.
///
/// # Safety
///
/// `registry` must point to a registry pointer. Its target's word 2 is a
/// 32-bit handler-table pointer and word 3 is its entry count. `type_id`
/// must point to at least one 32-bit word. As in retailOS, neither pointer is
/// NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn typed_handler_registry_lookup(
    registry: *mut *mut u8,
    type_id: *const u32,
    direction: u32,
    flags: u32,
    default_entry: usize,
) -> *mut u8 {
    let registry_words = (*registry).cast::<u32>();
    let type_index = type_id.read();
    let handler = if type_index < registry_words.add(3).read() {
        let table = registry_words.add(2).read() as usize as *const u32;
        table.add(type_index as usize).read() as usize as *mut u8
    } else {
        core::ptr::null_mut()
    };

    if handler.is_null() {
        typed_handler_registry_slow_lookup(registry, type_id, direction, flags, default_entry)
    } else {
        handler
    }
}

#[cfg(all(test, not(target_os = "none")))]
pub static TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{LazyLock, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const TABLE_WORD: usize = 0x40;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TYPED_HANDLER_REGISTRY_LOOKUP, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static mut FALLBACK_CALL: Option<(*mut *mut u8, *const u32, u32, u32, usize)> = None;
    static mut FALLBACK_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_slow_lookup(
        registry: *mut *mut u8,
        type_id: *const u32,
        direction: u32,
        flags: u32,
        default_entry: usize,
    ) -> *mut u8 {
        FALLBACK_CALL = Some((registry, type_id, direction, flags, default_entry));
        FALLBACK_RESULT
    }

    fn install_recorder(result: *mut u8) -> MutexGuard<'static, ()> {
        let guard = TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(FALLBACK_CALL).write(None);
            addr_of_mut!(FALLBACK_RESULT).write(result);
            addr_of_mut!(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP).write(recording_slow_lookup);
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP).write(missing_typed_handler_registry_slow_lookup);
        }
        drop(guard);
    }

    unsafe fn fixture_registry(entry_count: u32, entries: &[u32]) -> Option<*mut u8> {
        let base = *FIXTURE;
        let Some(base) = base else {
            assert!(note_missing_u32_fixture("app::typed_handler_registry_lookup"));
            return None;
        };
        let base = base as *mut u8;
        core::ptr::write_bytes(base, 0, FIXTURE_LEN);
        let words = base.cast::<u32>();
        words.add(2).write(base.add(TABLE_WORD) as usize as u32);
        words.add(3).write(entry_count);
        for (index, entry) in entries.iter().enumerate() {
            base.add(TABLE_WORD).cast::<u32>().add(index).write(*entry);
        }
        Some(base)
    }

    #[test]
    fn returns_nonzero_in_range_table_entry_without_fallback() {
        let _guard = TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(mut registry) = (unsafe { fixture_registry(3, &[0, 0x1234_5678, 0]) }) else {
            return;
        };
        let type_id = [1];

        let returned = unsafe { typed_handler_registry_lookup(addr_of_mut!(registry), type_id.as_ptr(), 7, 0x80, 0x083a_b410) };

        assert_eq!(returned as usize, 0x1234_5678);
    }

    #[test]
    fn delegates_zero_and_out_of_range_entries_with_all_arguments() {
        let result = 0x8765_4321usize as *mut u8;
        let guard = install_recorder(result);
        let Some(mut registry) = (unsafe { fixture_registry(2, &[0x1111_1111, 0]) }) else {
            restore_default(guard);
            return;
        };
        let type_id = [1];

        let returned = unsafe { typed_handler_registry_lookup(addr_of_mut!(registry), type_id.as_ptr(), 3, 0x20, 0x083a_b410) };

        assert_eq!(returned, result);
        unsafe {
            assert_eq!(addr_of!(FALLBACK_CALL).read(), Some((addr_of_mut!(registry), type_id.as_ptr(), 3, 0x20, 0x083a_b410)));
        }

        let out_of_range = [2];
        let returned = unsafe { typed_handler_registry_lookup(addr_of_mut!(registry), out_of_range.as_ptr(), 1, 0x80, 0xdead_beef) };

        assert_eq!(returned, result);
        unsafe {
            assert_eq!(addr_of!(FALLBACK_CALL).read(), Some((addr_of_mut!(registry), out_of_range.as_ptr(), 1, 0x80, 0xdead_beef)));
        }
        restore_default(guard);
    }
}
