//! `object_record_at` — `FUN_0829ae4c` @ `0x0829ae4c` (8 bytes; 3 inbound
//! plain `bl` call sites, no predicated calls).
//!
//! Raw ARM establishes the two-word extent 0x0829ae4c..0x0829ae53: `add
//! r0,r0,#0x4c; b 0x0829c01c`. The next separately entered function begins at
//! 0x0829ae54 with `stmdb sp!,{r3-r7,lr}`. The tail target reads its argument's
//! word at +0x0c and adds `index * 8`; therefore this wrapper returns the
//! eight-byte record at the pointer stored in the original object's +0x58
//! field. Full-image A32 decoding finds inbound plain calls at 0x08130fbc,
//! 0x08131338, and 0x081313e0, with no predicated `bl` callers and no `bl` in
//! this tail-call wrapper. Deliberate deviations: the recovered tail target is
//! inlined rather than exposed as a separate Rust seam.

/// Returns the `index`th eight-byte record from the table pointer at +0x58.
///
/// # Safety
/// `object` must be valid to read an aligned target-width word at byte offset
/// 0x58. The resulting record pointer is not validated; retailOS performs no
/// null or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_record_at(object: *const u8, index: u32) -> *mut u8 {
    let records = unsafe { object.add(0x58).cast::<u32>().read() as *mut u8 };
    records.wrapping_add(index.wrapping_mul(8) as usize)
}

#[cfg(test)]
mod tests {
    use super::object_record_at;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn resolves_records_from_the_word_at_offset_0x58() {
        let Some(slab) = try_map_u32_slab(hints::OBJECT_RECORD_AT, 0x1000) else {
            assert!(note_missing_u32_fixture("util/object_record_at"));
            return;
        };
        let records = unsafe { slab.add(0x100) };
        unsafe { slab.add(0x58).cast::<u32>().write(records as usize as u32) };
        unsafe { slab.add(0x5c).cast::<u32>().write(0xa5a5_a5a5) };

        for index in 0..5 {
            assert_eq!(
                unsafe { object_record_at(slab, index) },
                unsafe { records.add(index as usize * 8) },
            );
        }
        assert_eq!(unsafe { slab.add(0x5c).cast::<u32>().read() }, 0xa5a5_a5a5);
    }
}
