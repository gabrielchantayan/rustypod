//! Reads a counted string through a UI object's 24-byte resource vector.
#[cfg(not(target_os = "none"))]
use crate::cxx::templates::VectorBounds;
use crate::cxx::templates::vector_size_elem24;
use crate::util::string_pool::{string_pool_read_counted, StringPool, PARAM_ERR};

use super::object_state::object_backend_for_kind;

const RESOURCE_VECTOR_OFFSET: usize = 0xeb0;
const RESOURCE_ENTRY_SIZE: usize = 24;
const BACKEND_POOL_POINTER_OFFSET: usize = 0xf60;
const STRING_POOL_OFFSET: usize = 0x1c8;

/// object_resource_vector24_counted_string — original: `FUN_080528ec` @
/// `0x080528ec` (108 bytes; next real function begins at `0x08052958`; four
/// inbound plain `bl` callers and no predicated-BL callers, binary-verified).
///
/// Raw ARM clears `counted[0]`, resolves a kind-1 backend or kind-2 proxy,
/// rejects a negative index or one outside the object `+0xeb0` vector of
/// 24-byte records with `-50`, then tail-branches to `string_pool_read_counted`
/// for the selected record's first word. Its two internal direct calls are plain
/// `bl` instructions to `object_backend_for_kind` and `vector_size_elem24`; the
/// counted reader is a tail branch, not the five-argument call Ghidra reports.
///
/// Deliberate deviation: the stock tail branch preserves the object pointer in
/// `r3`, which is dead because the counted reader clears its local byte-length
/// output before consuming it. Rust passes deterministic zero instead.
///
/// # Safety
///
/// `counted` is written before validation and must be valid. `object` must
/// satisfy `object_backend_for_kind`; accepted indices require a readable vector,
/// record table, resolved backend, and inline string pool.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_resource_vector24_counted_string(
    object: *const u8,
    index: i32,
    counted: *mut u16,
) -> i32 {
    counted.write(0);
    let backend = object_backend_for_kind(object);
    if index < 0 {
        return PARAM_ERR;
    }

    #[cfg(target_os = "none")]
    let vector = object.add(RESOURCE_VECTOR_OFFSET).cast::<crate::cxx::templates::VectorBounds>();
    #[cfg(not(target_os = "none"))]
    let vector_storage = {
        let vector_words = object.add(RESOURCE_VECTOR_OFFSET).cast::<u32>();
        VectorBounds {
            begin: vector_words.read() as usize as *mut u8,
            end: vector_words.add(1).read() as usize as *mut u8,
        }
    };
    #[cfg(not(target_os = "none"))]
    let vector = &vector_storage;
    if index >= vector_size_elem24(vector) {
        return PARAM_ERR;
    }

    let entry_id = (object.add(RESOURCE_VECTOR_OFFSET).cast::<u32>().read() as usize as *const u8)
        .add(index as usize * RESOURCE_ENTRY_SIZE)
        .cast::<i32>()
        .read();
    let pool_base = (backend.add(BACKEND_POOL_POINTER_OFFSET).cast::<u32>().read() as usize) as *mut u8;
    let pool = pool_base.add(STRING_POOL_OFFSET).cast::<StringPool>();
    string_pool_read_counted(pool, entry_id, counted, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use core::mem::MaybeUninit;

    const OBJECT_BYTES: usize = 0x2000;

    unsafe fn fixture() -> Option<*mut u8> {
        try_map_u32_slab(hints::OBJECT_RESOURCE_VECTOR24_COUNTED_STRING, OBJECT_BYTES)
    }

    #[test]
    fn clears_output_before_rejecting_negative_and_out_of_range_indices() {
        let Some(object) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("ui/object_resource_vector24_counted_string"));
            return;
        };
        unsafe {
            object.write(1);
            let table = object.add(0x1000);
            (object.add(RESOURCE_VECTOR_OFFSET) as *mut u32).write(table as usize as u32);
            (object.add(RESOURCE_VECTOR_OFFSET + 4) as *mut u32).write(table.add(RESOURCE_ENTRY_SIZE) as usize as u32);
            let mut counted = 0xffffu16;
            assert_eq!(object_resource_vector24_counted_string(object, -1, &mut counted), PARAM_ERR);
            assert_eq!(counted, 0);
            counted = 0xffff;
            assert_eq!(object_resource_vector24_counted_string(object, 1, &mut counted), PARAM_ERR);
            assert_eq!(counted, 0);
        }
    }

    #[test]
    fn reads_the_second_twenty_four_byte_record_through_the_backend_pool() {
        let Some(object) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("ui/object_resource_vector24_counted_string"));
            return;
        };
        unsafe {
            object.write(1);
            let table = object.add(0x1000);
            (object.add(RESOURCE_VECTOR_OFFSET) as *mut u32).write(table as usize as u32);
            (object.add(RESOURCE_VECTOR_OFFSET + 4) as *mut u32).write(table.add(RESOURCE_ENTRY_SIZE * 2) as usize as u32);
            (table as *mut i32).write(1);
            (table.add(RESOURCE_ENTRY_SIZE) as *mut i32).write(0);
            (object.add(BACKEND_POOL_POINTER_OFFSET) as *mut u32).write(object as usize as u32);
            let pool = object.add(STRING_POOL_OFFSET).cast::<StringPool>();
            pool.write(MaybeUninit::<StringPool>::zeroed().assume_init());
            (*pool).tag = 0x7374_7263;
            let mut counted = 0xffffu16;
            assert_eq!(object_resource_vector24_counted_string(object, 1, &mut counted), 0);
            assert_eq!(counted, 0);
            assert_eq!((*pool).lock_depth, 0);
        }
    }
}
