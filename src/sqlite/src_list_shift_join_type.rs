//! Shifting SQLite FROM-clause join types.
//!
//! `src_list_shift_join_type` — retailOS `FUN_083845dc` at load address
//! `0x083845dc`, 60 bytes (`0x083845dc..0x08384614`, bounded by the next
//! separately linked function at `0x08384618`). Raw whole-image ARM B/BL
//! decoding finds two direct inbound call sites, both unconditional plain
//! `bl`; there are no predicated calls.
//!
//! This is SQLite 3.5.x's `sqlite3SrcListShiftJoinType`. Except for the
//! firmware's two sentinel no-op pointers (NULL and `0xfffffff8`), it shifts
//! the join-type byte at +0x1d down an inline 0x30-byte `SrcList` item array,
//! then clears the first byte. The signed `nSrc` halfword is deliberately
//! re-read only once, matching the ARM routine. No deliberate deviations.

const N_SRC: usize = 0x00;
const FIRST_JOIN_TYPE: usize = 0x1d;
const ITEM_STRIDE: usize = 0x30;

/// `sqlite3SrcListShiftJoinType` — retailOS `FUN_083845dc` @ `0x083845dc`
/// (60 bytes; two unconditional plain `bl` call sites).
///
/// # Safety
/// `source_list` must be NULL, `0xfffffff8`, or name a writable target-layout
/// `SrcList` with its signed `nSrc` halfword at +0x00 and enough 0x30-byte
/// entries for that count.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn src_list_shift_join_type(source_list: *mut u8) {
    if source_list.is_null() || source_list as usize == usize::MAX - 7 {
        return;
    }

    let mut index = i32::from(core::ptr::read(source_list.add(N_SRC).cast::<i16>()));
    while {
        index -= 1;
        index > 0
    } {
        let source = source_list.add(FIRST_JOIN_TYPE + (index as usize - 1) * ITEM_STRIDE);
        let destination = source.add(ITEM_STRIDE);
        core::ptr::write(destination, core::ptr::read(source));
    }
    core::ptr::write(source_list.add(FIRST_JOIN_TYPE), 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST_SIZE: usize = FIRST_JOIN_TYPE + 4 * ITEM_STRIDE + 1;

    #[repr(align(4))]
    struct SourceListBytes([u8; LIST_SIZE]);

    impl SourceListBytes {
        fn with_count(count: i16) -> Self {
            let mut list = Self([0xa5; LIST_SIZE]);
            list.0[..2].copy_from_slice(&count.to_le_bytes());
            list
        }

        fn join_type(&self, index: usize) -> u8 {
            self.0[FIRST_JOIN_TYPE + index * ITEM_STRIDE]
        }

        fn set_join_type(&mut self, index: usize, value: u8) {
            self.0[FIRST_JOIN_TYPE + index * ITEM_STRIDE] = value;
        }
    }

    #[test]
    fn shifts_each_join_type_toward_higher_items() {
        let mut list = SourceListBytes::with_count(4);
        list.set_join_type(0, 0x11);
        list.set_join_type(1, 0x22);
        list.set_join_type(2, 0x33);
        list.set_join_type(3, 0x44);

        unsafe { src_list_shift_join_type(list.0.as_mut_ptr()) };

        assert_eq!(list.join_type(0), 0);
        assert_eq!(list.join_type(1), 0x11);
        assert_eq!(list.join_type(2), 0x22);
        assert_eq!(list.join_type(3), 0x33);
        assert_eq!(list.0[FIRST_JOIN_TYPE + 1], 0xa5, "adjacent fields stay untouched");
    }

    #[test]
    fn nonpositive_and_single_counts_only_clear_the_first_join_type() {
        for count in [-2, 0, 1] {
            let mut list = SourceListBytes::with_count(count);
            list.set_join_type(0, 0x11);
            list.set_join_type(1, 0x22);
            unsafe { src_list_shift_join_type(list.0.as_mut_ptr()) };
            assert_eq!(list.join_type(0), 0, "count {count}");
            assert_eq!(list.join_type(1), 0x22, "count {count}");
        }
    }

    #[test]
    fn sentinel_pointers_are_noops() {
        unsafe {
            src_list_shift_join_type(core::ptr::null_mut());
            src_list_shift_join_type((usize::MAX - 7) as *mut u8);
        }
    }
}
