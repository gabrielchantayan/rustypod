//! Reads a counted string from a kind-resolved UI object's resource table.
#[cfg(target_os = "none")]
use core::mem;

use crate::cxx::templates::{vector_size_elem16, VectorBounds};
use crate::util::string_pool::{string_pool_read_counted, StringPool, PARAM_ERR};
use crate::util::tagged_counter::{tagged_counter_try_decrement, tagged_counter_try_increment, TaggedCounter};

use super::object_state::object_backend_for_kind;

const RESOURCE_TABLE_VECTOR_OFFSET: usize = 0xebc;
const RESOURCE_ENTRY_SIZE: usize = 16;
const STRING_POOL_OFFSET: usize = 0xcc;

type BackendActiveItem = unsafe extern "C" fn(*const u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_backend_active_item(backend: *const u8) -> *mut u8 {
    mem::transmute::<usize, BackendActiveItem>(0x0805_4724)(backend)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_backend_active_item(_: *const u8) -> *mut u8 {
    panic!("FUN_08054724 is unported; install OBJECT_RESOURCE_ACTIVE_ITEM")
}

#[cfg(target_os = "none")]
static mut OBJECT_RESOURCE_ACTIVE_ITEM: BackendActiveItem = firmware_backend_active_item;
#[cfg(all(not(target_os = "none"), not(test)))]
static mut OBJECT_RESOURCE_ACTIVE_ITEM: BackendActiveItem = missing_backend_active_item;

#[inline(always)]
unsafe fn resource_entry_count(vector: *const VectorBounds) -> i32 {
    #[cfg(target_pointer_width = "32")]
    {
        vector_size_elem16(vector)
    }
    #[cfg(not(target_pointer_width = "32"))]
    {
        let begin = vector.cast::<u32>().read_unaligned();
        let end = vector.cast::<u32>().add(1).read_unaligned();
        end.wrapping_sub(begin).wrapping_shr(4) as i32
    }
}
#[cfg(test)]
static mut OBJECT_RESOURCE_ACTIVE_ITEM: BackendActiveItem = missing_backend_active_item;

/// object_resource_counted_string — original: `FUN_08053084` @ `0x08053084`
/// (144 bytes; next real function starts at `0x08053114`; **4 plain `bl`
/// callers and no predicated-BL callers**).
///
/// Raw ARM establishes six internal plain calls: `object_backend_for_kind`,
/// `vector_size_elem16`, the unported active-item resolver at `0x08054724`,
/// `tagged_counter_try_increment`, `string_pool_read_counted`, and
/// `tagged_counter_try_decrement`. It clears `counted[0]` before validation,
/// rejects a null output, negative index, or index outside the object's
/// `+0xebc` 16-byte-entry vector with `-50`, then reads that entry's first
/// word through the active item's inline pool at `+0xcc`.
///
/// Deliberate deviation: `FUN_08054724` has no recovered identity beyond its
/// observed backend-to-active-item contract, so it remains a target call and
/// replaceable host seam rather than an invented Rust implementation. The
/// reader's fourth ABI argument is dead after its callee clears the local
/// byte length; zero supplies it deterministically.
///
/// # Safety
///
/// `object`, `counted`, its `+0xebc` vector, and every accepted table entry
/// must be readable; `counted` is written before its null check, as retailOS
/// does. The active-item seam must return an item with a valid string pool at
/// `+0xcc`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_resource_counted_string(
    object: *const u8,
    index: i32,
    counted: *mut u16,
) -> i32 {
    counted.write(0);
    let backend = object_backend_for_kind(object);
    if counted.is_null() || index < 0 {
        return PARAM_ERR;
    }

    let entries = object.add(RESOURCE_TABLE_VECTOR_OFFSET).cast::<VectorBounds>();
    if index >= resource_entry_count(entries) {
        return PARAM_ERR;
    }

    let item = (core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_RESOURCE_ACTIVE_ITEM)))(backend);
    let pool = item.add(STRING_POOL_OFFSET).cast::<StringPool>();
    let _ = tagged_counter_try_increment(pool.cast::<TaggedCounter>());
    let entry_table = (entries.cast::<u32>().read() as usize) as *const u8;
    let entry_id = entry_table.add(index as usize * RESOURCE_ENTRY_SIZE).cast::<i32>().read();
    let status = string_pool_read_counted(pool, entry_id, counted, 0);
    let _ = tagged_counter_try_decrement(pool.cast::<TaggedCounter>());
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use core::mem::MaybeUninit;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ACTIVE_ITEM: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn active_item(_: *const u8) -> *mut u8 { ACTIVE_ITEM }

    #[test]
    fn rejects_negative_and_out_of_range_indices_before_the_active_item_lookup() {
        let _lock = TEST_LOCK.lock();
        let Some(object) = try_map_u32_slab(hints::OBJECT_RESOURCE_COUNTED_STRING, 0x2000) else {
            assert!(note_missing_u32_fixture("ui/object_resource_counted_string"));
            return;
        };
        unsafe {
            object.write(1);
            let table = object.add(0x1000);
            (object.add(RESOURCE_TABLE_VECTOR_OFFSET) as *mut u32).write(table as usize as u32);
            (object.add(RESOURCE_TABLE_VECTOR_OFFSET + 4) as *mut u32).write(table.add(16) as usize as u32);
            OBJECT_RESOURCE_ACTIVE_ITEM = active_item;
            let mut counted = 0xffffu16;
            assert_eq!(object_resource_counted_string(object, -1, &mut counted), PARAM_ERR);
            assert_eq!(counted, 0);
            counted = 0xffff;
            assert_eq!(object_resource_counted_string(object, 1, &mut counted), PARAM_ERR);
            assert_eq!(counted, 0);
            OBJECT_RESOURCE_ACTIVE_ITEM = missing_backend_active_item;
        }
    }

    #[test]
    fn reads_zero_id_and_restores_the_inline_pool_counter() {
        let _lock = TEST_LOCK.lock();
        let Some(object) = try_map_u32_slab(hints::OBJECT_RESOURCE_COUNTED_STRING_VALID, 0x2000) else {
            assert!(note_missing_u32_fixture("ui/object_resource_counted_string"));
            return;
        };
        let mut pool = unsafe { MaybeUninit::<StringPool>::zeroed().assume_init() };
        pool.tag = 0x7374_7263;
        unsafe {
            object.write(1);
            let table = object.add(0x1000);
            (object.add(RESOURCE_TABLE_VECTOR_OFFSET) as *mut u32).write(table as usize as u32);
            (object.add(RESOURCE_TABLE_VECTOR_OFFSET + 4) as *mut u32).write(table.add(16) as usize as u32);
            (table as *mut i32).write(0);
            ACTIVE_ITEM = (core::ptr::addr_of_mut!(pool) as *mut u8).sub(STRING_POOL_OFFSET);
            OBJECT_RESOURCE_ACTIVE_ITEM = active_item;
            let mut counted = 0xffffu16;
            assert_eq!(object_resource_counted_string(object, 0, &mut counted), 0);
            assert_eq!(counted, 0);
            assert_eq!(pool.lock_depth, 0);
            OBJECT_RESOURCE_ACTIVE_ITEM = missing_backend_active_item;
        }
    }
}
