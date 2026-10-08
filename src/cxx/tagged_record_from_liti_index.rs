//! Indexed tagged record construction — `FUN_08106cf4` @ `0x08106cf4`.
//!
//! True extent: 84 bytes, `0x08106cf4..0x08106d48`; the next instruction
//! starts a separate function. Raw ARM verifies three outgoing plain BLs
//! (two to tagged_record_init, one to liti_indexed_entry_lookup), zero
//! predicated BLs; whole-image decoding finds two incoming plain BLs and
//! zero predicated BLs.
//!
//! Initialize out with zero payload/flag. For a nonnegative signed index,
//! look up the entry in the object addressed by source word zero, then copy
//! that payload and source byte +4 into out. Copy the flag even when lookup
//! returns zero. Initialization precedes source reads, including for aliases.
//!
//! Deliberate codegen deviation: omit the temporary stack record initializer
//! and copy its two observable fields directly; its descriptor is never used.
//! The saved r3 word is only temporary storage, not a fourth semantic argument.
//! No behavioral deviations; the incidental r0 on exit is not a return value.

use crate::app::liti_indexed_entry_lookup::liti_indexed_entry_lookup;
use crate::cxx::tagged_record::{tagged_record_init, TaggedRecord};

/// # Safety
/// `out` must satisfy tagged_record_init's writable/aligned record contract.
/// For nonnegative indices, source must be aligned and readable through +4;
/// its first word must satisfy liti_indexed_entry_lookup's object contract
/// after the initial output stores. Source and output may alias.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_record_from_liti_index")]
#[inline(never)]
pub unsafe extern "C" fn tagged_record_from_liti_index(
    out: *mut TaggedRecord,
    source: *const u32,
    index: i32,
) {
    unsafe { tagged_record_init(out, 0, 0) };
    if index < 0 {
        return;
    }
    let object = unsafe { source.read_volatile() } as usize as *const u8;
    let payload = unsafe { liti_indexed_entry_lookup(object, index as u32) };
    let flag = unsafe { source.cast::<u8>().add(4).read_volatile() };
    unsafe {
        core::ptr::addr_of_mut!((*out).payload).write_volatile(payload);
        core::ptr::addr_of_mut!((*out).flag).write_volatile(flag);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::tagged_record::TAGGED_RECORD_DESCRIPTOR;

    #[test]
    fn negative_index_initializes_without_accessing_source_and_preserves_padding() {
        for index in [i32::MIN, -1] {
            let mut words = [0xffff_ffffu32; 3];
            unsafe { tagged_record_from_liti_index(words.as_mut_ptr().cast(), core::ptr::null(), index) };
            assert_eq!(words, [TAGGED_RECORD_DESCRIPTOR, 0, 0xffff_ff00]);
        }
    }

    #[test]
    fn copies_lookup_payload_and_flag_including_failed_lookup() {
        let Some(base) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TAGGED_RECORD_FROM_LITI_INDEX, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("cxx::tagged_record_from_liti_index"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(base, 0, 0x1000);
            let object = base.add(0x100).cast::<u32>();
            let target = base.add(0x200).cast::<u32>();
            let table = base.add(0x300).cast::<u32>();
            target.write(0x6974_696c);
            object.add(1).write(target as usize as u32);
            object.add(6).write(2);
            object.add(7).write(table as usize as u32);
            table.write(0x1234_5678);
            table.add(1).write(0xdead_beef);
            let mut source = [object as usize as u32, 0xaabb_ccd5];
            for (index, expected) in [(0, 0x1234_5678), (1, 0xdead_beef), (2, 0), (i32::MAX, 0)] {
                let mut out = [0xffff_ffffu32; 3];
                tagged_record_from_liti_index(out.as_mut_ptr().cast(), source.as_ptr(), index);
                assert_eq!(out, [TAGGED_RECORD_DESCRIPTOR, expected, 0xffff_ffd5]);
            }
            source[0] = 0;
            let mut out = [0xffff_ffffu32; 3];
            tagged_record_from_liti_index(out.as_mut_ptr().cast(), source.as_ptr(), 0);
            assert_eq!(out, [TAGGED_RECORD_DESCRIPTOR, 0, 0xffff_ffd5]);

            // Source word zero aliases output payload: initialization must
            // replace its valid object pointer with NULL before the lookup.
            let mut aliased = [0, object as usize as u32, 0x1122_33e7];
            tagged_record_from_liti_index(aliased.as_mut_ptr().cast(), aliased.as_ptr().add(1), 0);
            assert_eq!(aliased, [TAGGED_RECORD_DESCRIPTOR, 0, 0x1122_3300]);
        }
    }
}
