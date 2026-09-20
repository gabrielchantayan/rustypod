//! `free_index_table_grow` — original: `FUN_083b479c` @ `0x083b479c` (148
//! bytes: 37 ARM words; the next separately linked function starts at
//! `0x083b4830`).
//!
//! **Verified call count:** three direct inbound `bl` call sites, all plain;
//! no predicated inbound calls. The body has two plain outbound `bl` calls,
//! to the already ported `operator_new_tag3` @ `0x082aad74` and
//! `operator_delete_tag3` @ `0x082aad14`.
//!
//! Grows a target-width free-index table `{slots, free_count, capacity,
//! free_head}`. Capacity becomes `max(capacity * 2, required_capacity)`;
//! existing slots are copied, the appended slots form an odd-tagged successor
//! chain, and the final slot is the `u32::MAX` end sentinel. It releases the
//! old slot array, then publishes the new array, free count, capacity, and
//! head in the original order.
//!
//! Deliberate deviations: none on target; host tests replace the two already
//! ported heap veneers only to make allocation and release observable.

use crate::heap::veneers::{operator_delete_tag3, operator_new_tag3};

#[cfg(test)]
type AllocateSlots = unsafe extern "C" fn(usize) -> *mut u8;
#[cfg(test)]
type ReleaseSlots = unsafe extern "C" fn(*mut u8);

#[cfg(test)]
static mut ALLOCATE_SLOTS: AllocateSlots = operator_new_tag3;
#[cfg(test)]
static mut RELEASE_SLOTS: ReleaseSlots = operator_delete_tag3;

#[cfg(test)]
unsafe fn allocate_slots(size: usize) -> *mut u8 {
    ALLOCATE_SLOTS(size)
}

#[cfg(not(test))]
unsafe fn allocate_slots(size: usize) -> *mut u8 {
    operator_new_tag3(size)
}

#[cfg(test)]
unsafe fn release_slots(slots: *mut u8) {
    RELEASE_SLOTS(slots);
}

#[cfg(not(test))]
unsafe fn release_slots(slots: *mut u8) {
    operator_delete_tag3(slots);
}

/// Grows `table` to hold at least `required_capacity` slots.
///
/// # Safety
/// `table` must point to four writable target words `{slots, free_count,
/// capacity, free_head}`. Its current `slots` word must be a valid aligned
/// target address for `capacity` readable words. The tag-3 allocator must
/// return `new_capacity * 4` writable bytes; as in retailOS, allocation
/// failure, NULL slots, and arithmetic overflow are not guarded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn free_index_table_grow(table: *mut u32, required_capacity: u32) {
    let old_capacity = table.add(2).read();
    let new_capacity = old_capacity.wrapping_mul(2).max(required_capacity);
    let new_slots = allocate_slots(new_capacity.wrapping_mul(4) as usize) as *mut u32;
    let old_slots = table.read() as usize as *mut u32;

    let mut index = 0;
    while index < old_capacity {
        new_slots.add(index as usize).write(old_slots.add(index as usize).read());
        index = index.wrapping_add(1);
    }

    while index < new_capacity.wrapping_sub(1) {
        new_slots.add(index as usize).write((index.wrapping_add(1) << 1) | 1);
        index = index.wrapping_add(1);
    }
    new_slots.add(new_capacity.wrapping_sub(1) as usize).write(u32::MAX);

    release_slots(old_slots as *mut u8);
    table.write(new_slots as usize as u32);
    table.add(1).write(new_capacity.wrapping_sub(old_capacity));
    table.add(2).write(new_capacity);
    table.add(3).write(old_capacity);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut NEW_SLOTS: [u32; 16] = [0; 16];
    static mut ALLOCATION_SIZE: usize = 0;
    static mut RELEASED_SLOTS: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_allocation(size: usize) -> *mut u8 {
        ALLOCATION_SIZE = size;
        core::ptr::addr_of_mut!(NEW_SLOTS).cast::<u8>()
    }

    unsafe extern "C" fn record_release(slots: *mut u8) {
        RELEASED_SLOTS = slots;
    }

    #[test]
    fn grows_by_double_or_required_capacity_and_rebuilds_the_free_chain() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::FREE_INDEX_TABLE_GROW, 64) else {
            return;
        };
        let table = slab.cast::<u32>();
        let old_slots = unsafe { table.add(4) };

        unsafe {
            ALLOCATE_SLOTS = record_allocation;
            RELEASE_SLOTS = record_release;
            old_slots.write(0x1111_1111);
            old_slots.add(1).write(0x2222_2222);
            table.write(old_slots as usize as u32);
            table.add(1).write(0);
            table.add(2).write(2);
            table.add(3).write(u32::MAX);

            free_index_table_grow(table, 3);

            assert_eq!(ALLOCATION_SIZE, 16);
            assert_eq!(RELEASED_SLOTS, old_slots.cast::<u8>());
            assert_eq!(NEW_SLOTS[..4], [0x1111_1111, 0x2222_2222, 7, u32::MAX]);
            assert_eq!(table.add(1).read(), 2);
            assert_eq!(table.add(2).read(), 4);
            assert_eq!(table.add(3).read(), 2);

            NEW_SLOTS.fill(0);
            old_slots.write(0xa);
            old_slots.add(1).write(0xb);
            table.write(old_slots as usize as u32);
            table.add(2).write(2);
            free_index_table_grow(table, 9);

            assert_eq!(ALLOCATION_SIZE, 36);
            assert_eq!(NEW_SLOTS[..9], [0xa, 0xb, 7, 9, 11, 13, 15, 17, u32::MAX]);
            assert_eq!(table.add(1).read(), 7);
            assert_eq!(table.add(2).read(), 9);
            assert_eq!(table.add(3).read(), 2);
        }
    }
}
