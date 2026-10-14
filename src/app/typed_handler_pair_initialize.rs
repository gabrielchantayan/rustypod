//! Initialize a pair of typed-handler subobjects.
//!
//! Original: FUN_083b6cac at 0x083b6cac; true extent 84 bytes through
//! 0x083b6d00 (76 code bytes and two literals). Whole-image aligned A32
//! decoding finds one incoming plain BL at 0x083b69b8, zero predicated BLs;
//! the body contains two plain BLs and zero predicated BLs.
//!
//! Resolve the primary handler, store it and its +0x10 subobject, then
//! resolve the type ID at 0x08a0fc28 with direction 1, flags 0x80, and
//! opaque default entry 0x083ab504. Store that result's +0x10 subobject
//! and return the destination. Neither result is NULL-checked.
//! Deliberate deviations: repr(C) pointers widen on hosts, and the fixed
//! type-ID words have a host fixture. No target behavioral deviations.

use super::type_handler_lookup_primary_id::type_handler_lookup_primary_id;
use super::typed_handler_registry_lookup::typed_handler_registry_lookup;

#[repr(C)]
pub struct TypedHandlerPair {
    pub primary: *mut u8,
    pub primary_subobject: *mut u8,
    pub secondary_subobject: *mut u8,
}

#[inline(always)]
fn secondary_type_id() -> *const u32 {
    #[cfg(target_os = "none")]
    { 0x08a0_fc28 as *const u32 }
    #[cfg(not(target_os = "none"))]
    {
        static TYPE_ID: [u32; 4] = [3482622105, 2216498925, 2806019701, 2945596477];
        TYPE_ID.as_ptr()
    }
}

/// # Safety
/// `out` must be writable and `registry` must satisfy the typed-handler
/// lookup contract, including any slow lookup invoked by either query.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn typed_handler_pair_initialize(
    out: *mut TypedHandlerPair,
    registry: *mut *mut u8,
) -> *mut TypedHandlerPair {
    let primary = type_handler_lookup_primary_id(registry);
    core::ptr::addr_of_mut!((*out).primary).write(primary);
    core::ptr::addr_of_mut!((*out).primary_subobject).write(primary.wrapping_add(0x10));
    let secondary = typed_handler_registry_lookup(
        registry, secondary_type_id(), 1, 0x80, 0x083a_b504,
    );
    core::ptr::addr_of_mut!((*out).secondary_subobject).write(secondary.wrapping_add(0x10));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::typed_handler_registry_lookup::{
        TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK, TYPED_HANDLER_REGISTRY_SLOW_LOOKUP,
    };
    use core::ptr::{addr_of, addr_of_mut, null_mut};

    static mut DESTINATION: *mut TypedHandlerPair = null_mut();
    static mut RESULTS: [*mut u8; 2] = [null_mut(); 2];
    static mut CALLS: usize = 0;
    static mut INTERMEDIATE: [usize; 3] = [0; 3];

    unsafe extern "C" fn resolve(
        _: *mut *mut u8, _: *const u32, _: u32, _: u32, _: usize,
    ) -> *mut u8 {
        let call = CALLS;
        if call == 1 {
            let out = DESTINATION;
            INTERMEDIATE = [(*out).primary as usize, (*out).primary_subobject as usize,
                (*out).secondary_subobject as usize];
        }
        CALLS += 1;
        RESULTS[call]
    }

    #[test]
    fn initializes_subobjects_in_order_without_null_guard_or_adjacent_writes() {
        let _guard = TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK.lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            let previous = addr_of!(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP).read();
            addr_of_mut!(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP).write(resolve);
            // Count zero forces both real fast lookups through the existing seam.
            let mut state = [0u32; 4];
            let mut registry = state.as_mut_ptr().cast::<u8>();
            for (primary, secondary) in [(0usize, 0usize), (0x1230, 0x9870),
                (usize::MAX - 7, usize::MAX - 15)] {
                #[repr(C)]
                struct Guarded { before: usize, pair: TypedHandlerPair, after: usize }
                let mut guarded = Guarded {
                    before: 0x1357,
                    pair: TypedHandlerPair { primary: 1usize as *mut u8,
                        primary_subobject: 2usize as *mut u8,
                        secondary_subobject: 3usize as *mut u8 },
                    after: 0x2468,
                };
                let out = addr_of_mut!(guarded.pair);
                DESTINATION = out;
                RESULTS = [primary as *mut u8, secondary as *mut u8];
                CALLS = 0;
                assert_eq!(typed_handler_pair_initialize(out, addr_of_mut!(registry)), out);
                assert_eq!(guarded.pair.primary as usize, primary);
                assert_eq!(guarded.pair.primary_subobject as usize, primary.wrapping_add(16));
                assert_eq!(guarded.pair.secondary_subobject as usize, secondary.wrapping_add(16));
                assert_eq!(addr_of!(INTERMEDIATE).read(), [primary, primary.wrapping_add(16), 3]);
                assert_eq!((guarded.before, guarded.after), (0x1357, 0x2468));
            }
            addr_of_mut!(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP).write(previous);
        }
    }
}
