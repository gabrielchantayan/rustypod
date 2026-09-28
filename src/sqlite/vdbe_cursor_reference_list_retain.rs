//! Retain every reference held by a VDBE cursor-reference list.
//!
//! `vdbe_cursor_reference_list_retain` — retailOS `FUN_083721f8` at load
//! address `0x083721f8` (76 bytes; true extent `0x083721f8..0x08372244`,
//! followed by the separately linked release counterpart). Raw ARM decoding
//! finds two inbound unconditional plain `bl` instructions (`0x08386efc` and
//! `0x0838b0cc`); no inbound predicated `bl` instructions. The function
//! itself contains no calls.
//!
//! It walks the signed count and target-width pointer words in the list,
//! increments each referenced object's word at `+0x0c`, and sets its byte
//! flag at `+0x0a` only when the flag is clear and byte `+0x09` is nonzero.
//! Deliberate deviation: none; host tests map the same 32-bit pointer layout
//! below 4 GiB.

const OBJECT_REFERENCE_COUNT_WORD: usize = 0x0c / 4;
const OBJECT_ELIGIBLE_FLAG_OFFSET: usize = 0x09;
const OBJECT_ACTIVE_FLAG_OFFSET: usize = 0x0a;

/// Retains the references described by `list`.
///
/// # Safety
///
/// `list` must address a target-width sequence containing a signed count
/// followed by that many valid object-pointer words. Every object pointer must
/// address an object with writable fields at `+0x0a` and `+0x0c`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vdbe_cursor_reference_list_retain(list: *mut u32) {
    let mut index = 0_i32;
    loop {
        let count = unsafe { list.read() as i32 };
        if index >= count {
            return;
        }

        let object = unsafe { list.add(index as usize + 1).read() as usize as *mut u8 };
        let reference_count = unsafe {
            object.add(OBJECT_REFERENCE_COUNT_WORD * size_of::<u32>()).cast::<u32>().read()
        };
        unsafe {
            object.add(OBJECT_REFERENCE_COUNT_WORD * size_of::<u32>()).cast::<u32>().write(reference_count.wrapping_add(1));
        }
        if unsafe { object.add(OBJECT_ACTIVE_FLAG_OFFSET).read() } == 0
            && unsafe { object.add(OBJECT_ELIGIBLE_FLAG_OFFSET).read() } != 0
        {
            unsafe { object.add(OBJECT_ACTIVE_FLAG_OFFSET).write(1) };
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    const FIXTURE_LEN: usize = 0x1000;
    const FIRST_OBJECT: usize = 0x100;
    const SECOND_OBJECT: usize = 0x140;
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<*mut u8> {
        try_map_u32_slab(hints::SQLITE_VDBE_CURSOR_REFERENCE_LIST_RETAIN, FIXTURE_LEN)
    }

    #[test]
    fn increments_all_entries_and_latches_only_eligible_inactive_references() {
        let _lock = TEST_LOCK.lock();
        let Some(base) = fixture() else {
            assert!(note_missing_u32_fixture("sqlite/vdbe_cursor_reference_list_retain"));
            return;
        };
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            let list = base.cast::<u32>();
            let first = base.add(FIRST_OBJECT);
            let second = base.add(SECOND_OBJECT);
            list.write(2);
            list.add(1).write(first as usize as u32);
            list.add(2).write(second as usize as u32);
            first.add(OBJECT_REFERENCE_COUNT_WORD * 4).cast::<u32>().write(1);
            first.add(OBJECT_ELIGIBLE_FLAG_OFFSET).write(1);
            second.add(OBJECT_REFERENCE_COUNT_WORD * 4).cast::<u32>().write(2);
            second.add(OBJECT_ELIGIBLE_FLAG_OFFSET).write(0);
            second.add(OBJECT_ACTIVE_FLAG_OFFSET).write(0x55);

            vdbe_cursor_reference_list_retain(list);

            assert_eq!(first.add(OBJECT_REFERENCE_COUNT_WORD * 4).cast::<u32>().read(), 2);
            assert_eq!(first.add(OBJECT_ACTIVE_FLAG_OFFSET).read(), 1);
            assert_eq!(second.add(OBJECT_REFERENCE_COUNT_WORD * 4).cast::<u32>().read(), 3);
            assert_eq!(second.add(OBJECT_ACTIVE_FLAG_OFFSET).read(), 0x55);
        }
    }

    #[test]
    fn ignores_nonpositive_counts_and_wraps_reference_count() {
        let _lock = TEST_LOCK.lock();
        let Some(base) = fixture() else {
            assert!(note_missing_u32_fixture("sqlite/vdbe_cursor_reference_list_retain"));
            return;
        };
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            let list = base.cast::<u32>();
            let object = base.add(FIRST_OBJECT);
            list.add(1).write(object as usize as u32);
            object.add(OBJECT_REFERENCE_COUNT_WORD * 4).cast::<u32>().write(u32::MAX);
            object.add(OBJECT_ELIGIBLE_FLAG_OFFSET).write(1);

            list.write(0);
            vdbe_cursor_reference_list_retain(list);
            list.write((-1_i32) as u32);
            vdbe_cursor_reference_list_retain(list);
            assert_eq!(object.add(OBJECT_REFERENCE_COUNT_WORD * 4).cast::<u32>().read(), u32::MAX);
            assert_eq!(object.add(OBJECT_ACTIVE_FLAG_OFFSET).read(), 0);

            list.write(1);
            vdbe_cursor_reference_list_retain(list);
            assert_eq!(object.add(OBJECT_REFERENCE_COUNT_WORD * 4).cast::<u32>().read(), 0);
            assert_eq!(object.add(OBJECT_ACTIVE_FLAG_OFFSET).read(), 1);
        }
    }
}
