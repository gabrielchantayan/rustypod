//! `type_handler_lookup_primary_id` — original: `FUN_083eaae0` @ **0x083eaae0**
//! (32 bytes of code plus literal-pool words at `0x083eab00` and
//! `0x083eab04`: 40 bytes of true extent, `0x083eaae0..0x083eab08`).
//!
//! The wrapper asks `typed_handler_registry_lookup` for the handler selected
//! by the four-word type identifier at `0x08a0fb9c`. It fixes the registry
//! arguments to `1` and `0x20`, and supplies the raw default entry
//! `0x083ab368`; that entry's identity is not established. The helper result
//! returns unchanged.
//!
//! **Two direct `bl` call sites, both unconditional and no predicated forms**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`:
//! `0x083b6cbc` and `0x083d82a8`.
//!
//! Deliberate deviation: none. The registry helper is now ported; its
//! unported slow fallback owns the target and host seam.

use crate::app::typed_handler_registry_lookup::typed_handler_registry_lookup;

const HANDLER_TYPE_ID_ADDRESS: usize = 0x08a0_fb9c;
const DEFAULT_HANDLER_ENTRY_ADDRESS: usize = 0x083a_b368;
const HANDLER_LOOKUP_DIRECTION: u32 = 1;
const HANDLER_LOOKUP_FLAGS: u32 = 0x20;

#[inline(always)]
fn handler_type_id() -> *const u32 {
    #[cfg(target_os = "none")]
    {
        HANDLER_TYPE_ID_ADDRESS as *const u32
    }

    #[cfg(not(target_os = "none"))]
    {
        static TYPE_ID: [u32; 4] = [0x7d51_5cf5, 0x42f6_df58, 0x6cd7_0935, 0x9ff4_111c];
        TYPE_ID.as_ptr()
    }
}

/// Looks up the handler for this wrapper's fixed, four-word type identifier.
///
/// # Safety
///
/// `registry` must satisfy the typed registry lookup's contract. The returned
/// opaque handler pointer is owned and interpreted by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn type_handler_lookup_primary_id(registry: *mut *mut u8) -> *mut u8 {
    typed_handler_registry_lookup(
        registry,
        handler_type_id(),
        HANDLER_LOOKUP_DIRECTION,
        HANDLER_LOOKUP_FLAGS,
        DEFAULT_HANDLER_ENTRY_ADDRESS,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::typed_handler_registry_lookup::{
        missing_typed_handler_registry_slow_lookup, TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK,
        TYPED_HANDLER_REGISTRY_SLOW_LOOKUP, TypedHandlerRegistryLookup,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TYPE_HANDLER_LOOKUP_PRIMARY_ID, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static mut LOOKUP_CALL: Option<(*mut *mut u8, [u32; 4], u32, u32, usize)> = None;
    static mut LOOKUP_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_slow_lookup(
        registry: *mut *mut u8,
        type_id: *const u32,
        direction: u32,
        flags: u32,
        default_entry: usize,
    ) -> *mut u8 {
        LOOKUP_CALL = Some((registry, [type_id.read(), type_id.add(1).read(), type_id.add(2).read(), type_id.add(3).read()], direction, flags, default_entry));
        LOOKUP_RESULT
    }

    #[test]
    fn forwards_fixed_identifier_and_registry_arguments() {
        let _guard = TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(registry_state) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app::type_handler_lookup_primary_id"));
            return;
        };
        let registry_state = registry_state as *mut u8;
        unsafe {
            core::ptr::write_bytes(registry_state, 0, FIXTURE_LEN);
            addr_of_mut!(LOOKUP_CALL).write(None);
            addr_of_mut!(LOOKUP_RESULT).write(0x4321usize as *mut u8);
            addr_of_mut!(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP).write(recording_slow_lookup as TypedHandlerRegistryLookup);
        }
        let mut registry_value = registry_state;

        let returned = unsafe { type_handler_lookup_primary_id(addr_of_mut!(registry_value)) };

        unsafe {
            assert_eq!(
                addr_of!(LOOKUP_CALL).read(),
                Some((
                    addr_of_mut!(registry_value),
                    [0x7d51_5cf5, 0x42f6_df58, 0x6cd7_0935, 0x9ff4_111c],
                    1,
                    0x20,
                    0x083a_b368,
                ))
            );
            assert_eq!(returned, addr_of!(LOOKUP_RESULT).read());
            addr_of_mut!(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP).write(missing_typed_handler_registry_slow_lookup);
        }
    }
}
