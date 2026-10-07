//! `base_vtable_value_init` — `FUN_0813b53c` @ `0x0813b53c`.
//!
//! True extent: 20 bytes, four A32 instructions through `bx lr` at
//! 0x0813b548 plus the 0x08984de4 literal at 0x0813b54c. The next real
//! function begins at 0x0813b550. Raw whole-image decoding verifies two
//! inbound plain BLs (0x080facd8, 0x080fb468), zero predicated BLs, and
//! zero internal calls. Store the supplied value at +4, install the base
//! vtable at +0, and return the unchanged storage pointer. Both callers
//! immediately replace the base vtable with a derived one.
//!
//! Deliberate deviations: no target behavior changes. The concrete class
//! and the meaning of its value are unverified; names describe only the
//! recovered layout. Keep the vtable as a target-width word on hosts too.

pub const BASE_VTABLE_VALUE_VTABLE: u32 = 0x0898_4de4;

#[repr(C)]
pub struct BaseVtableValue {
    pub vtable: u32,
    pub value: u32,
}

/// Initialize the two-word base prefix, returning the original pointer.
///
/// # Safety
/// `storage` must point to at least two writable, aligned u32 words.
/// No NULL or bounds checks are performed by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn base_vtable_value_init(storage: *mut BaseVtableValue, value: u32) -> *mut BaseVtableValue {
    unsafe {
        core::ptr::addr_of_mut!((*storage).value).write_volatile(value);
        core::ptr::addr_of_mut!((*storage).vtable).write_volatile(BASE_VTABLE_VALUE_VTABLE);
    }
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_only_the_prefix_preserving_all_value_bits_and_pointer() {
        #[repr(C)]
        struct Guarded {
            before: u32,
            base: BaseVtableValue,
            after: [u32; 2],
        }
        for value in [0, 1, 0x8000_0000, 0x0898_4de4, u32::MAX] {
            let mut fixture = Guarded {
                before: 0x1234_5678,
                base: BaseVtableValue { vtable: u32::MAX, value: !value },
                after: [0x8765_4321, 0xdead_beef],
            };
            let storage = &mut fixture.base as *mut BaseVtableValue;
            let returned = unsafe { base_vtable_value_init(storage, value) };
            assert_eq!(returned, storage);
            assert_eq!(fixture.base.vtable, BASE_VTABLE_VALUE_VTABLE);
            assert_eq!(fixture.base.value, value);
            assert_eq!(fixture.before, 0x1234_5678);
            assert_eq!(fixture.after, [0x8765_4321, 0xdead_beef]);
            // Reconstruct an existing derived object with a different value.
            fixture.base.vtable = 0x0898_0000;
            unsafe { base_vtable_value_init(storage, !value); }
            assert_eq!(fixture.base.vtable, BASE_VTABLE_VALUE_VTABLE);
            assert_eq!(fixture.base.value, !value);
            assert_eq!(fixture.after, [0x8765_4321, 0xdead_beef]);
        }
    }
}
