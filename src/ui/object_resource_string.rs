//! Reads a counted resource string through a UI object's 12-byte resource table.
use crate::cxx::templates::{vector_size_elem12, VectorBounds};
use crate::util::string_pool::{string_pool_read_counted, StringPool, PARAM_ERR};

use super::object_state::object_backend_for_kind;

const RESOURCE_TABLE_VECTOR_OFFSET: usize = 0xe58;
const RESOURCE_ENTRY_SIZE: usize = 12;
const BACKEND_POOL_POINTER_OFFSET: usize = 0xf60;
const STRING_POOL_OFFSET: usize = 0x278;

/// object_resource_string — original: `FUN_08052e1c` @ `0x08052e1c` (116
/// bytes; four direct plain `bl` callers and no predicated-BL callers).
///
/// Raw ARM begins at `stmdb sp!,{r4-r8,lr}` and ends with its tail `b
/// 0x080bd8bc`; `0x08052e90` is the next separately entered function. It
/// clears `counted[0]`, resolves the kind-1/kind-2 backend, rejects negative
/// indices and indices outside the object's `+0xe58` vector of 12-byte
/// records with `-50`, then tail-calls the counted string-pool reader for the
/// record's first word.
///
/// Deliberate deviation: the firmware passes the still-live object pointer as
/// the counted reader's dead fourth argument. Zero is deterministic because
/// that reader clears its local byte-length output before consuming it.
///
/// # Safety
///
/// `object` and `counted` must be writable/readable as retailOS requires:
/// `counted[0]` is written before validation, and a valid record requires the
/// object vector, its table, resolved backend, and inline string pool to be
/// readable at their documented offsets.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_resource_string(
    object: *const u8,
    index: i32,
    counted: *mut u16,
) -> i32 {
    counted.write(0);
    let backend = object_backend_for_kind(object);
    if index < 0 {
        return PARAM_ERR;
    }

    let vector_words = object.add(RESOURCE_TABLE_VECTOR_OFFSET).cast::<u32>();
    let vector = VectorBounds {
        begin: vector_words.read() as usize as *mut u8,
        end: vector_words.add(1).read() as usize as *mut u8,
    };
    if index >= vector_size_elem12(&vector) {
        return PARAM_ERR;
    }

    let entry_table = vector.begin as *const u8;
    let entry_id = entry_table.add(index as usize * RESOURCE_ENTRY_SIZE).cast::<i32>().read();
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
        try_map_u32_slab(hints::OBJECT_RESOURCE_STRING, OBJECT_BYTES)
    }

    #[test]
    fn clears_output_and_rejects_negative_and_out_of_range_indices() {
        let Some(object) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("ui/object_resource_string"));
            return;
        };
        unsafe {
            object.write(1);
            let table = object.add(0x1000);
            (object.add(RESOURCE_TABLE_VECTOR_OFFSET) as *mut u32).write(table as usize as u32);
            (object.add(RESOURCE_TABLE_VECTOR_OFFSET + 4) as *mut u32).write(table.add(RESOURCE_ENTRY_SIZE) as usize as u32);
            let mut counted = 0xffffu16;
            assert_eq!(object_resource_string(object, -1, &mut counted), PARAM_ERR);
            assert_eq!(counted, 0);
            counted = 0xffff;
            assert_eq!(object_resource_string(object, 1, &mut counted), PARAM_ERR);
            assert_eq!(counted, 0);
        }
    }

    #[test]
    fn reads_the_selected_record_id_and_returns_a_zero_length_counted_string() {
        let Some(object) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("ui/object_resource_string"));
            return;
        };
        unsafe {
            object.write(1);
            let table = object.add(0x1000);
            (object.add(RESOURCE_TABLE_VECTOR_OFFSET) as *mut u32).write(table as usize as u32);
            (object.add(RESOURCE_TABLE_VECTOR_OFFSET + 4) as *mut u32).write(table.add(RESOURCE_ENTRY_SIZE * 2) as usize as u32);
            (table as *mut i32).write(0);
            (table.add(RESOURCE_ENTRY_SIZE) as *mut i32).write(0);
            (object.add(BACKEND_POOL_POINTER_OFFSET) as *mut u32).write(object as usize as u32);
            let pool = object.add(STRING_POOL_OFFSET).cast::<StringPool>();
            pool.write(MaybeUninit::<StringPool>::zeroed().assume_init());
            (*pool).tag = 0x7374_7263;
            let mut counted = 0xffffu16;
            assert_eq!(object_resource_string(object, 1, &mut counted), 0);
            assert_eq!(counted, 0);
            assert_eq!((*pool).lock_depth, 0);
        }
    }
}
