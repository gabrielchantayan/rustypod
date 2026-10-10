//! Facade word query — retailOS `FUN_080a28a4` at load address 0x080a28a4.
//! True extent: 92 bytes, next function starts at 0x080a2900. Whole-image
//! A32 decoding verifies two inbound plain BLs and zero predicated BLs;
//! the body has four plain BLs, zero predicated BLs, and one indirect BLX.
//!
//! Acquire the selected registry entry and its counted-mutex guard, resolve
//! a matching facade, then call vtable slot +0x98 with a mutable stack copy
//! of incoming r2 and the caller's output word. Clear the output on any
//! nonzero status, release the guard, and return the status unchanged.
//! The slot's domain-specific meaning is not established by the callers.
//! Deliberate deviations: reuse existing ports for all four direct callees;
//! host vtable pointers widen natively, so slot +0x98 is indexed as word 38.
//! No new firmware seams, validation, or error paths.

use crate::app::facade_registry_walk::{facade_registry_walk, RegistryFacade};
use crate::app::trace_buffer::{trace_buffer_get, trace_buffer_slot_acquire};
use crate::kernel::sync_mutex::{counted_mutex_guard_release, CountedMutex};

unsafe fn dispatch_query_word(
    facade: *mut RegistryFacade,
    output: *mut u32,
    mut query_word: u32,
    guard: *mut *mut CountedMutex,
) -> i32 {
    let query: unsafe extern "C" fn(*mut RegistryFacade, *mut u32, *mut u32) -> i32 =
        core::mem::transmute(((*facade).vtable as *const usize).add(0x98 / 4).read());
    let status = query(facade, &mut query_word, output);
    if status != 0 {
        output.write(0);
    }
    counted_mutex_guard_release(guard);
    status
}

/// Query vtable word 38 of the selected matching facade while holding its
/// entry guard. `query_word` is passed by mutable address, not by value.
///
/// # Safety
/// The registry must be initialized; `output` must be writable and the
/// selected facade must provide the retailOS slot +0x98 ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn facade_query_word(
    selector: u32,
    output: *mut u32,
    query_word: u32,
) -> i32 {
    let mut guard = core::ptr::null_mut();
    let entry = trace_buffer_slot_acquire(trace_buffer_get().cast(), selector, &mut guard);
    let facade = facade_registry_walk(entry.cast(), 1);
    dispatch_query_word(facade, output, query_word, &mut guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct QueryFacade {
        facade: RegistryFacade,
        status: i32,
    }

    unsafe extern "C" fn query(
        facade: *mut RegistryFacade, input: *mut u32, output: *mut u32,
    ) -> i32 {
        // Exercise a genuine in/out argument: update the private query copy,
        // and produce a result distinct from both the input and old output.
        let value = input.read().rotate_left(7) ^ 0xa5a5_5a5a;
        input.write(value);
        output.write(value.wrapping_add(1));
        (*(facade.cast::<QueryFacade>())).status
    }

    #[test]
    fn success_preserves_result_and_query_is_a_private_mutable_copy() {
        unsafe {
            let mut slots = [0usize; 39];
            slots[38] = query as *const () as usize;
            let mut object = QueryFacade {
                facade: RegistryFacade { vtable: slots.as_ptr() as usize,
                    opaque_04: 0, kind_08: 1, pad_09: [0; 3] },
                status: 0,
            };
            for input in [0u32, 1, 0x8000_0000, u32::MAX] {
                let mut output = 0xdead_beef;
                let mut guard = core::ptr::null_mut();
                assert_eq!(dispatch_query_word(&mut object.facade, &mut output, input, &mut guard), 0);
                assert_eq!(output, (input.rotate_left(7) ^ 0xa5a5_5a5a).wrapping_add(1));
            }
        }
    }

    #[test]
    fn every_nonzero_status_clears_even_a_result_written_by_the_method() {
        unsafe {
            let mut slots = [0usize; 39];
            slots[38] = query as *const () as usize;
            let mut object = QueryFacade {
                facade: RegistryFacade { vtable: slots.as_ptr() as usize,
                    opaque_04: 0, kind_08: 1, pad_09: [0; 3] },
                status: 0,
            };
            for status in [1, -1, i32::MIN, i32::MAX] {
                object.status = status;
                let mut output = 0xdead_beef;
                let mut guard = core::ptr::null_mut();
                assert_eq!(dispatch_query_word(&mut object.facade, &mut output, 17, &mut guard), status);
                assert_eq!(output, 0);
            }
        }
    }
}
