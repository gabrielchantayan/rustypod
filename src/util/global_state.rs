//! Lookup of a global-state record by name.
//!
//! `global_state_slot_find` — original: `FUN_08077ff0` @ `0x08077ff0`
//! (**140 bytes**, `0x08077ff0..0x08077ff0`; the next independently linked
//! function begins at `0x0807807c`). Verified three incoming plain `bl` call
//! sites at `0x08078094`, `0x08078160`, and `0x080781b4`; the body makes two
//! plain calls (`__rt_udiv` and the `strcmp` veneer) and no predicated calls.
//!
//! Algorithm: hash the NUL-terminated name with `hash = byte + hash * 31`,
//! use the unsigned-divide remainder to select a slot from the table's bucket
//! array, then scan slots backward with wraparound until a NULL slot or an
//! equal NUL-terminated name. The table stores its bucket count at `+0x04`
//! and u32 bucket-array address at `+0x0c`; each non-NULL bucket word points
//! to a record whose first word is its name pointer. Deliberate deviation:
//! the port calls the already-ported `__rt_udivmod` and `strcmp` directly,
//! rather than reproducing their ADS r1 return state and `strcmp` veneer.

#[cfg(test)]
use core::ptr;

const BUCKET_COUNT_OFFSET: usize = 0x04;
const BUCKET_ARRAY_OFFSET: usize = 0x0c;


/// Finds the target-layout bucket slot for `global_name` in
/// `global_state_table`. Neither input nor the bucket count is validated,
/// matching the retail routine.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_state_slot_find(
    global_name: *const u8,
    global_state_table: *const u8,
) -> *mut u32 {
    let mut hash = 0u32;
    let mut name_cursor = global_name;
    loop {
        let byte = unsafe { name_cursor.read() };
        if byte == 0 {
            break;
        }
        hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
        name_cursor = unsafe { name_cursor.add(1) };
    }

    let bucket_count = unsafe { global_state_table.add(BUCKET_COUNT_OFFSET).cast::<u32>().read() };
    let bucket_array = unsafe {
        global_state_table.add(BUCKET_ARRAY_OFFSET).cast::<u32>().read() as usize as *mut u32
    };
    let mut remainder = 0;
    unsafe { crate::runtime::rt_div::__rt_udivmod(hash, bucket_count, &mut remainder) };
    let first_slot = unsafe { bucket_array.add(remainder as usize) };
    let mut slot = first_slot;
    loop {
        let record = unsafe { slot.read() as usize as *const u8 };
        if record.is_null() {
            return slot;
        }
        let record_name = unsafe { record.cast::<u32>().read() as usize as *const u8 };
        if unsafe { record_name.read() } == unsafe { global_name.read() }
            && unsafe { crate::libc::strcmp::strcmp(record_name, global_name) } == 0 {
            return slot;
        }
        slot = if slot == bucket_array {
            unsafe { bucket_array.add(bucket_count as usize - 1) }
        } else {
            unsafe { slot.sub(1) }
        };
    }
}

/// `global_state_get` — original: `FUN_080781b0` @ `0x080781b0` (16 bytes).
///
/// Finds the name's table slot and returns its first word, with no null check
/// or validation, exactly as the raw `bl; ldr r0,[r0]` wrapper does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_state_get(
    global_name: *const u8,
    global_state_table: *const u8,
) -> *mut u8 {
    unsafe { global_state_slot_find(global_name, global_state_table).read() as usize as *mut u8 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn finds_a_same_prefix_name_after_wrapping_backward() {
        let Some(slab) = try_map_u32_slab(hints::GLOBAL_STATE_SLOT_FIND, 0x1000) else {
            note_missing_u32_fixture("util::global_state");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let table = slab;
            let buckets = slab.add(0x40).cast::<u32>();
            let mismatch = slab.add(0x100).cast::<u32>();
            let matched = slab.add(0x120).cast::<u32>();
            let mismatch_name = slab.add(0x200);
            let matched_name = slab.add(0x220);
            ptr::copy_nonoverlapping(b"alpine\0".as_ptr(), mismatch_name, 7);
            ptr::copy_nonoverlapping(b"alpha\0".as_ptr(), matched_name, 6);
            mismatch.write(mismatch_name as usize as u32);
            matched.write(matched_name as usize as u32);
            table.add(BUCKET_COUNT_OFFSET).cast::<u32>().write(3);
            table.add(BUCKET_ARRAY_OFFSET).cast::<u32>().write(buckets as usize as u32);

            let first_index = 2;
            buckets.add(first_index).write(mismatch as usize as u32);
            buckets.add(1).write(mismatch as usize as u32);
            buckets.write(matched as usize as u32);
            assert_eq!(
                global_state_slot_find(matched_name, table),
                buckets,
                "the backward scan wraps from slot zero to the last slot",
            );
            assert_eq!(global_state_get(matched_name, table), matched.cast());
        }
    }

    #[test]
    fn returns_the_null_bucket_slot_for_an_absent_name() {
        let Some(slab) = try_map_u32_slab(hints::GLOBAL_STATE_SLOT_FIND, 0x1000) else {
            note_missing_u32_fixture("util::global_state");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let table = slab;
            let buckets = slab.add(0x40).cast::<u32>();
            table.add(BUCKET_COUNT_OFFSET).cast::<u32>().write(1);
            table.add(BUCKET_ARRAY_OFFSET).cast::<u32>().write(buckets as usize as u32);
            assert_eq!(global_state_slot_find(b"missing\0".as_ptr(), table), buckets);
        }
    }
}
