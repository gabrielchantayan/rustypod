//! Reads a counted string through a kind-resolved object's resource-id table.
use crate::util::string_pool::{string_pool_read_counted, StringPool, PARAM_ERR};

use super::object_state::object_backend_for_kind;

const RESOURCE_ID_TABLE_OFFSET: usize = 0xe70;
const RESOURCE_ID_COUNT_OFFSET: usize = 0xe78;
const BACKEND_POOL_POINTER_OFFSET: usize = 0xf60;
const STRING_POOL_OFFSET: usize = 0x118;

/// object_resource_table_counted_string — original: `FUN_08052c64` @
/// `0x08052c64` (84 bytes; next real function begins at `0x08052cb8`; four
/// direct plain `bl` callers and no predicated-BL callers, binary-verified).
///
/// Raw ARM clears `counted[0]`, resolves a kind-1 backend or kind-2 proxy,
/// rejects a negative or out-of-range index with `-50`, then tail-branches to
/// `string_pool_read_counted` for the selected resource ID. The pool is at
/// `*(backend + 0xf60) + 0x118`; the resource IDs and count are at
/// `object + 0xe70` and `object + 0xe78` respectively. Its sole internal
/// direct call is the plain `bl` to `object_backend_for_kind`; the reader is a
/// conditional tail branch to `0x080bd8bc`.
///
/// Deliberate deviation: none. The stock tail branch preserves the index in
/// `r3` as the counted reader's dead initial-byte-length argument; this port
/// passes that same bit pattern.
///
/// # Safety
///
/// `counted` is written before validation and must be valid. `object` must
/// satisfy `object_backend_for_kind`; accepted indices require readable
/// resource count/table fields and a valid inline string pool.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_resource_table_counted_string(
    object: *const u8,
    index: i32,
    counted: *mut u16,
) -> i32 {
    counted.write(0);
    let backend = object_backend_for_kind(object);
    if index < 0 || (index as u32) >= object.add(RESOURCE_ID_COUNT_OFFSET).cast::<u32>().read() {
        return PARAM_ERR;
    }

    let entry_id = (object.add(RESOURCE_ID_TABLE_OFFSET).cast::<u32>().read() as usize as *const i32)
        .add(index as usize)
        .read();
    let pool_base = (backend.add(BACKEND_POOL_POINTER_OFFSET).cast::<u32>().read() as usize) as *mut u8;
    let pool = pool_base.add(STRING_POOL_OFFSET).cast::<StringPool>();
    string_pool_read_counted(pool, entry_id, counted, index as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use core::mem::MaybeUninit;

    const OBJECT_BYTES: usize = 0x2000;

    unsafe fn fixture() -> Option<*mut u8> {
        try_map_u32_slab(hints::OBJECT_RESOURCE_TABLE_COUNTED_STRING, OBJECT_BYTES)
    }

    #[test]
    fn clears_output_before_rejecting_negative_and_out_of_range_indices() {
        let Some(object) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("ui/object_resource_table_counted_string"));
            return;
        };
        unsafe {
            object.write(1);
            (object.add(RESOURCE_ID_COUNT_OFFSET) as *mut u32).write(1);
            let mut counted = 0xffffu16;
            assert_eq!(object_resource_table_counted_string(object, -1, &mut counted), PARAM_ERR);
            assert_eq!(counted, 0);
            counted = 0xffff;
            assert_eq!(object_resource_table_counted_string(object, 1, &mut counted), PARAM_ERR);
            assert_eq!(counted, 0);
        }
    }

    #[test]
    fn reads_selected_id_through_resolved_backend_pool() {
        let Some(object) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("ui/object_resource_table_counted_string"));
            return;
        };
        unsafe {
            object.write(1);
            let table = object.add(0x1000);
            (object.add(RESOURCE_ID_TABLE_OFFSET) as *mut u32).write(table as usize as u32);
            (object.add(RESOURCE_ID_COUNT_OFFSET) as *mut u32).write(2);
            (table as *mut i32).write(1);
            (table.add(4) as *mut i32).write(0);
            (object.add(BACKEND_POOL_POINTER_OFFSET) as *mut u32).write(object as usize as u32);
            let pool = object.add(STRING_POOL_OFFSET).cast::<StringPool>();
            pool.write(MaybeUninit::<StringPool>::zeroed().assume_init());
            (*pool).tag = 0x7374_7263;
            let mut counted = 0xffffu16;
            assert_eq!(object_resource_table_counted_string(object, 1, &mut counted), 0);
            assert_eq!(counted, 0);
            assert_eq!((*pool).lock_depth, 0);
        }
    }
}
