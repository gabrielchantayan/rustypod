use crate::ft::memory::{ft_mem_realloc, FtMemory};

/// Appends a blank 16-byte stem record — original `FUN_080b089c` @
/// 0x080b089c (160 bytes; 1 plain `bl`, 0 predicated `bl`; 3 direct `bl`
/// caller sites).
///
/// The three-word target-width array header holds `count`, `capacity`, and a
/// record pointer. When full, capacity rounds `count + 1` up to eight records
/// and [`ft_mem_realloc`] grows the 16-byte record array. On success the new
/// record's first and fourth words are cleared, the count advances, and its
/// address is returned through `out_record`. Allocation failure leaves the
/// header unchanged and returns the allocator error with a null output.
///
/// Deliberate deviation: target pointers remain `u32` words rather than host
/// pointers so the firmware layout is preserved; the caller must supply a
/// target-addressable record buffer on host tests.
///
/// # Safety
/// `records` and `out_record` must be valid target-width objects. If growth is
/// required, `memory` must satisfy [`ft_mem_realloc`]'s safety contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn psh_dimension_append_stem_record(
    records: *mut u32,
    memory: *mut FtMemory,
    out_record: *mut u32,
) -> i32 {
    let count = *records;
    let next_count = count.wrapping_add(1);
    let capacity = *records.add(1);
    let mut error = 0;

    if capacity < next_count {
        let next_capacity = next_count.wrapping_add(7) & !7;
        let block = *records.add(2) as usize as *mut u8;
        let grown = ft_mem_realloc(
            memory,
            16,
            capacity as i32,
            next_capacity as i32,
            block,
            &mut error,
        );
        *records.add(2) = grown as usize as u32;
        if error == 0 {
            *records.add(1) = next_capacity;
        }
    }

    let record = if error == 0 {
        let record = ((*records.add(2) as usize as *mut u8).add(next_count as usize * 16 - 16)).cast::<u32>();
        *record = 0;
        *record.add(3) = 0;
        *records = next_count;
        record as usize as u32
    } else {
        0
    };
    *out_record = record;
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn appends_at_count_and_clears_only_outer_stem_words() {
        let Some(slab) = try_map_u32_slab(hints::PSH_DIMENSION_APPEND_STEM_RECORD, 0x1000) else { return; };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let header = slab.cast::<u32>();
            let records = slab.add(0x100).cast::<u32>();
            *header = 1;
            *header.add(1) = 2;
            *header.add(2) = records as usize as u32;
            let mut output = u32::MAX;

            assert_eq!(psh_dimension_append_stem_record(header, core::ptr::null_mut(), &mut output), 0);
            assert_eq!(*header, 2);
            assert_eq!(*header.add(1), 2);
            assert_eq!(output, records.add(4) as usize as u32);
            assert_eq!(*records.add(4), 0);
            assert_eq!(*records.add(7), 0);
            assert_eq!(*records.add(5), 0xa5a5_a5a5);
            assert_eq!(*records.add(6), 0xa5a5_a5a5);
        }
    }

    #[test]
    fn uses_the_last_existing_capacity_slot_without_allocator() {
        let Some(slab) = try_map_u32_slab(hints::PSH_DIMENSION_APPEND_STEM_RECORD_CAPACITY, 0x1000) else { return; };
        unsafe {
            slab.write_bytes(0xff, 0x1000);
            let header = slab.cast::<u32>();
            let records = slab.add(0x100).cast::<u32>();
            *header = 7;
            *header.add(1) = 8;
            *header.add(2) = records as usize as u32;
            let mut output = 0;

            assert_eq!(psh_dimension_append_stem_record(header, core::ptr::null_mut(), &mut output), 0);
            assert_eq!(*header, 8);
            assert_eq!(*header.add(1), 8);
            assert_eq!(output, records.add(28) as usize as u32);
            assert_eq!(*records.add(28), 0);
            assert_eq!(*records.add(31), 0);
        }
    }
}
