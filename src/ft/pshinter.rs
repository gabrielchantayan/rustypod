use crate::ft::memory::{ft_mem_realloc, FtMemory};

/// Release a PostScript hint mask table — FUN_080a92c4 @ 0x080a92c4.
/// True extent [0x080a92c4, 0x080a9328): 100 bytes; the next word is a
/// fresh PUSH prologue. Two plain BLs to ft_mem_free @ 0x082cfae8, zero
/// predicated BLs; two incoming plain BLs in FUN_080a3c28.
///
/// Snapshot capacity (word 1) and the record array (word 2). For every
/// allocated four-word mask, free its byte buffer at word 2, then clear
/// words 2, 0, 1, and 3. Reload and free the header's array pointer, then
/// clear header words 2, 0, and 1. Active count does not limit cleanup.
/// Deliberate deviation: Rust replaces register/post-index addressing;
/// target pointers remain u32 words, matching this module's existing ABI.
/// The existing allocator port may inline its null-guarded callback.
///
/// # Safety
/// `table` is a writable three-word header; its capacity-sized record array
/// is writable and all non-null buffers belong to `memory`. Callbacks must
/// keep the header and record storage alive until their final release.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn psh_mask_table_done(table: *mut u32, memory: *mut FtMemory) {
    let mut remaining = table.add(1).read();
    let mut mask = (table.add(2).read() as usize) as *mut u32;
    while remaining != 0 {
        crate::ft::memory::ft_mem_free(memory, (mask.add(2).read() as usize) as *mut u8);
        mask.add(2).write(0);
        mask.write(0);
        mask.add(1).write(0);
        mask.add(3).write(0);
        mask = mask.add(4);
        remaining -= 1;
    }
    crate::ft::memory::ft_mem_free(memory, (table.add(2).read() as usize) as *mut u8);
    table.add(2).write(0);
    table.write(0);
    table.add(1).write(0);
}

#[cfg(test)]
mod mask_table_done_tests {
    extern crate std;
    use super::*;

    struct Recorder {
        table: *mut u32,
        records: *mut u32,
        calls: std::vec::Vec<(usize, [u32; 3], [u32; 12])>,
    }
    unsafe extern "C" fn free(memory: *mut FtMemory, block: *mut u8) {
        let recorder = &mut *((*memory).user as *mut Recorder);
        let header = [recorder.table.read(), recorder.table.add(1).read(),
                      recorder.table.add(2).read()];
        let mut records = [0; 12];
        records.copy_from_slice(core::slice::from_raw_parts(recorder.records, 12));
        recorder.calls.push((block as usize, header, records));
    }
    unsafe extern "C" fn alloc(_: *mut FtMemory, _: i32) -> *mut u8 {
        panic!("cleanup must not allocate")
    }
    unsafe extern "C" fn realloc(_: *mut FtMemory, _: i32, _: i32, _: *mut u8) -> *mut u8 {
        panic!("cleanup must not reallocate")
    }

    #[test]
    fn capacity_cleanup_preserves_callback_state_and_trailing_storage() {
        use crate::testing::{hints, try_map_u32_slab};
        let Some(slab) = try_map_u32_slab(hints::PSH_MASK_TABLE_DONE, 0x1000) else { return; };
        unsafe {
            let records = slab.cast::<u32>();
            let base = records as usize as u32;
            for capacity in 0..=3 {
                for present in 0..8 {
                    let mut state = [0u32; 12];
                    for i in 0..3 {
                        state[i * 4..i * 4 + 4].copy_from_slice(&[
                            11 + i as u32, 21 + i as u32,
                            if present & (1 << i) != 0 { base + 128 + i as u32 * 16 } else { 0 },
                            31 + i as u32,
                        ]);
                    }
                    core::ptr::copy_nonoverlapping(state.as_ptr(), records, 12);
                    let mut header = [0, capacity, base, 0xabcdef01];
                    let original = [0, capacity, base];
                    let mut expected = std::vec::Vec::new();
                    for i in 0..capacity as usize {
                        if state[i * 4 + 2] != 0 {
                            expected.push((state[i * 4 + 2] as usize, original, state));
                        }
                        state[i * 4..i * 4 + 4].fill(0);
                    }
                    expected.push((base as usize, original, state));
                    let mut recorder = Recorder { table: header.as_mut_ptr(), records,
                        calls: std::vec::Vec::new() };
                    let mut memory = FtMemory {
                        user: (&mut recorder as *mut Recorder).cast(), alloc, free, realloc,
                    };
                    psh_mask_table_done(header.as_mut_ptr(), &mut memory);
                    assert_eq!(recorder.calls, expected, "capacity {capacity}, mask {present}");
                    assert_eq!(header, [0, 0, 0, 0xabcdef01]);
                    assert_eq!(core::slice::from_raw_parts(records, 12), &state);
                    psh_mask_table_done(header.as_mut_ptr(), core::ptr::null_mut());
                    assert_eq!(recorder.calls, expected);
                }
            }
        }
    }
}

/// Selects the last stem record, appending one if empty — FUN_080a9328
/// @ 0x080a9328, true extent 68 bytes through 0x080a936c.
/// Raw A32 decoding: two inbound plain BLs (0x080cd950, 0x080d9ce4),
/// one outbound plain BL to psh_dimension_append_stem_record, no predicated
/// BLs. Nonempty arrays return base + count * 16 - 16 without mutation;
/// empty arrays return the append status and its output, including NULL on
/// failure. Deliberate deviations: Rust branches replace ARM predication;
/// target addresses remain u32 on hosts. Ghidra's fourth argument is spurious:
/// the stack slot is overwritten on both paths before it is read.
///
/// # Safety
/// `records` is a readable three-word header and `out_record` is writable.
/// Empty arrays must satisfy psh_dimension_append_stem_record's contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn psh_dimension_last_or_append_stem_record(
    records: *mut u32, memory: *mut FtMemory, out_record: *mut u32,
) -> i32 {
    let count = *records;
    let mut record = 0;
    let error = if count != 0 {
        record = (*records.add(2)).wrapping_add(count.wrapping_mul(16)).wrapping_sub(16);
        0
    } else {
        psh_dimension_append_stem_record(records, memory, &mut record)
    };
    *out_record = record;
    error
}

#[cfg(test)]
mod last_or_append_tests {
    use super::*;

    #[test]
    fn existing_records_use_wrapping_target_addresses_and_preserve_header() {
        for count in [1u32, 2, 0x1000_0000, u32::MAX] {
            let mut header = [count, 0xdead_beef, 0xffff_fff8];
            let original = header;
            let mut output = 7;
            assert_eq!(unsafe { psh_dimension_last_or_append_stem_record(header.as_mut_ptr(), core::ptr::null_mut(), &mut output) }, 0);
            assert_eq!(output, 0xffff_fff8u32.wrapping_add(count.wrapping_mul(16)).wrapping_sub(16));
            assert_eq!(header, original);
        }
    }

    #[test]
    fn empty_array_appends_once_then_reuses_record_and_reports_growth_failure() {
        use crate::testing::{hints, try_map_u32_slab};
        let Some(slab) = try_map_u32_slab(hints::PSH_DIMENSION_LAST_OR_APPEND, 0x1000) else { return; };
        unsafe {
            let records = slab.cast::<u32>();
            for i in 0..8 { records.add(i).write(0xa5a5_a5a5); }
            let base = records as usize as u32;
            let mut header = [0, 2, base];
            let mut output = 7;
            assert_eq!(psh_dimension_last_or_append_stem_record(header.as_mut_ptr(), core::ptr::null_mut(), &mut output), 0);
            assert_eq!(header, [1, 2, base]);
            assert_eq!(output, base);
            assert_eq!(core::slice::from_raw_parts(records, 8), &[0, 0xa5a5_a5a5, 0xa5a5_a5a5, 0, 0xa5a5_a5a5, 0xa5a5_a5a5, 0xa5a5_a5a5, 0xa5a5_a5a5]);
            records.write(42);
            assert_eq!(psh_dimension_last_or_append_stem_record(header.as_mut_ptr(), core::ptr::null_mut(), &mut output), 0);
            assert_eq!(header, [1, 2, base]);
            assert_eq!(records.read(), 42);
            // Exercise the real append and allocator failure path.
            unsafe extern "C" fn fail_alloc(_: *mut FtMemory, _: i32) -> *mut u8 { core::ptr::null_mut() }
            unsafe extern "C" fn free(_: *mut FtMemory, _: *mut u8) {}
            unsafe extern "C" fn realloc(_: *mut FtMemory, _: i32, _: i32, _: *mut u8) -> *mut u8 { core::ptr::null_mut() }
            let mut memory = FtMemory { user: core::ptr::null_mut(), alloc: fail_alloc, free, realloc };
            header = [0, 0, 0];
            output = 7;
            assert_eq!(psh_dimension_last_or_append_stem_record(header.as_mut_ptr(), &mut memory, &mut output), crate::ft::error::FT_ERR_OUT_OF_MEMORY);
            assert_eq!(header, [0, 0, 0]);
            assert_eq!(output, 0);
            assert_eq!(records.read(), 42);
        }
    }
}

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

/// Scales a dimension's stem widths — original `FUN_080d4898` @
/// 0x080d4898 (144 bytes, next function at 0x080d4928; 2 plain BL sites,
/// 0 predicated BL sites, both to `ft_mulfix` @ 0x0804d2cc).
///
/// Selects a 51-word (0xcc-byte) dimension, reads its count at word 1 and
/// 16.16 scale at word 50, and scales the width triples starting at word 2.
/// The first scaled width is the reference: subsequent widths whose signed,
/// wrapping absolute difference is less than 128 reuse it. Each scaled width
/// also gets a grid-rounded value `(width + 32) & !63`. Zero count writes
/// nothing. No deliberate behavioral deviations; word indexing preserves
/// the target layout on hosts, including ARM's wrapping signed arithmetic.
///
/// # Safety
/// `dimensions` must point to aligned, writable 51-word dimension records;
/// `dimension` must select a valid record, whose count is at most 16.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn psh_dimension_scale_widths(dimensions: *mut i32, dimension: u32) {
    let selected = dimensions.add(dimension.wrapping_mul(51) as usize);
    let mut remaining = *selected.add(1) as u32;
    let scale = *selected.add(50);
    if remaining == 0 {
        return;
    }
    let first = selected.add(2);
    let reference = crate::ft::calc::ft_mulfix(*first, scale);
    *first.add(1) = reference;
    *first.add(2) = reference.wrapping_add(32) & !63;
    remaining = remaining.wrapping_sub(1);
    let mut width = first.add(3);
    while remaining != 0 {
        let mut scaled = crate::ft::calc::ft_mulfix(*width, scale);
        let difference = scaled.wrapping_sub(reference);
        let magnitude = if difference < 0 { difference.wrapping_neg() } else { difference };
        if magnitude < 128 {
            scaled = reference;
        }
        *width.add(1) = scaled;
        *width.add(2) = scaled.wrapping_add(32) & !63;
        width = width.add(3);
        remaining = remaining.wrapping_sub(1);
    }
}

#[cfg(test)]
mod scale_width_tests {
    use super::psh_dimension_scale_widths;

    #[test]
    fn empty_dimension_preserves_every_word() {
        let mut dimensions = [0x12345678; 102];
        dimensions[52] = 0;
        let original = dimensions;
        unsafe { psh_dimension_scale_widths(dimensions.as_mut_ptr(), 1); }
        assert_eq!(dimensions, original);
    }

    #[test]
    fn selected_dimension_snaps_strictly_to_first_and_preserves_inputs() {
        let mut dimensions = [0x12345678; 102];
        let widths = [1000, 1127, 1128, 873, 872, 1254, 1380];
        dimensions[52] = widths.len() as i32;
        dimensions[101] = 0x10000;
        for (i, width) in widths.iter().enumerate() {
            dimensions[53 + i * 3] = *width;
        }
        let mut expected = dimensions;
        for (i, scaled) in [1000i32, 1000, 1128, 1000, 872, 1254, 1380].iter().enumerate() {
            expected[54 + i * 3] = *scaled;
            expected[55 + i * 3] = scaled.wrapping_add(32) & !63;
        }
        unsafe { psh_dimension_scale_widths(dimensions.as_mut_ptr(), 1); }
        assert_eq!(dimensions, expected);
    }

    #[test]
    fn negative_half_scale_and_grid_ties() {
        let mut dimension = [0; 51];
        dimension[1] = 4;
        dimension[50] = -0x8000;
        for (i, input) in [64, 320, 576, -64].iter().enumerate() {
            dimension[2 + i * 3] = *input;
        }
        unsafe { psh_dimension_scale_widths(dimension.as_mut_ptr(), 0); }
        assert_eq!([dimension[3], dimension[6], dimension[9], dimension[12]], [-32, -160, -288, -32]);
        assert_eq!([dimension[4], dimension[7], dimension[10], dimension[13]], [0, -128, -256, 0]);
    }

    #[test]
    fn signed_absolute_minimum_and_rounding_wrap_like_arm() {
        let mut dimension = [0; 51];
        dimension[1] = 3;
        dimension[50] = 0x10000;
        dimension[2] = i32::MAX;
        dimension[5] = -1; // difference is MIN; wrapping abs stays negative.
        dimension[8] = i32::MIN; // difference wraps to 1.
        unsafe { psh_dimension_scale_widths(dimension.as_mut_ptr(), 0); }
        for i in 0..3 {
            assert_eq!(dimension[3 + 3 * i], i32::MAX);
            assert_eq!(dimension[4 + 3 * i], i32::MIN);
        }
    }
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

/// Records a PostScript hint — original `FUN_080c151c` @ 0x080c151c.
/// True code size: 180 bytes (ends at 0x080c15d0; diagnostic strings follow,
/// next function at 0x080c1638). Raw words contain 0 plain BL and 0
/// predicated BL sites; two conditional tail branches reach ft_error_trace.
///
/// Rejects an unsigned out-of-range index, skips hints already marked with
/// flag 4, then marks the hint and links word 5 to the first recorded hint
/// whose signed intervals overlap, including touching endpoints. Endpoint
/// addition wraps at 32 bits. Appends the hint to the recorded-pointer array
/// unless full; the full-array error retains the flag and overlap link.
///
/// Deliberate deviations: uses the existing trace sink contract; unused
/// variadic slots are zero rather than incidental ARM register values.
/// Pointer fields remain u32 words to preserve the firmware layout on hosts.
///
/// # Safety
/// `table` must contain the target-width header (capacity, recorded count,
/// hints pointer, unused word, recorded-pointer array). Valid indices select
/// writable seven-word hints; recorded pointers must select readable hints.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn psh_hint_table_record(table: *mut u32, index: u32) {
    let capacity = *table;
    if index >= capacity {
        crate::ft::trace::ft_error_trace(
            b"psh_hint_table_record: invalid hint index %d\n\0".as_ptr(), index, 0, 0,
        );
        return;
    }
    let hint = (*table.add(2) as usize as *mut u32).add(index as usize * 7);
    let flags = *hint.add(4);
    if flags & 4 != 0 {
        return;
    }
    *hint.add(4) = flags | 4;
    *hint.add(5) = 0;
    let recorded = *table.add(4) as usize as *mut u32;
    let count = *table.add(1);
    for slot in 0..count {
        let previous_address = *recorded.add(slot as usize);
        let previous = previous_address as usize as *const u32;
        let start = *hint as i32;
        let end = start.wrapping_add(*hint.add(1) as i32);
        let previous_start = *previous as i32;
        if end >= previous_start
            && previous_start.wrapping_add(*previous.add(1) as i32) >= start
        {
            *hint.add(5) = previous_address;
            break;
        }
    }
    let count = *table.add(1);
    if count >= *table {
        crate::ft::trace::ft_error_trace(
            b"psh_hint_table_record: too many sorted hints!  BUG!\n\0".as_ptr(), 0, 0, 0,
        );
        return;
    }
    *table.add(1) = count.wrapping_add(1);
    *recorded.add(count as usize) = hint as usize as u32;
}

#[cfg(test)]
mod record_hint_tests {
    use super::psh_hint_table_record;
    use crate::ft::trace::{capture, TEST_TRACE_LOCK};

    #[test]
    fn interval_boundaries_duplicate_and_error_transitions() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PSH_HINT_TABLE_RECORD, 4096,
        ) else { return; };
        unsafe {
            let table = slab.cast::<u32>();
            let hints = table.add(16);
            let recorded = table.add(64);
            // Candidate interval, two earlier intervals, expected first overlap.
            let cases = [
                ((10i32, 5i32), (0i32, 9i32), (16i32, 2i32), None),
                ((10, 5), (0, 10), (15, 2), Some(0)),
                ((10, 5), (16, 1), (15, 2), Some(1)),
                ((-10, 0), (-10, 0), (0, 1), Some(0)),
                ((i32::MAX, 1), (i32::MIN, -1), (0, 0), Some(0)),
                ((i32::MAX, 1), (0, 0), (1, 0), None),
            ];
            for (candidate, first, second, overlap) in cases {
                core::ptr::write_bytes(table, 0, 80);
                *table = 3;
                *table.add(1) = 2;
                *table.add(2) = hints as usize as u32;
                *table.add(4) = recorded as usize as u32;
                for (i, (start, length)) in [first, second, candidate].iter().enumerate() {
                    *hints.add(i * 7) = *start as u32;
                    *hints.add(i * 7 + 1) = *length as u32;
                    *hints.add(i * 7 + 4) = 0x80;
                    *hints.add(i * 7 + 5) = 0xdeadbeef;
                }
                *recorded = hints as usize as u32;
                *recorded.add(1) = hints.add(7) as usize as u32;
                psh_hint_table_record(table, 2);
                assert_eq!(*table.add(1), 3);
                assert_eq!(*recorded.add(2), hints.add(14) as usize as u32);
                assert_eq!(*hints.add(18), 0x84);
                assert_eq!(*hints.add(19), overlap.map_or(0, |i| hints.add(i * 7) as usize as u32));
                let snapshot = core::slice::from_raw_parts(table, 80).to_vec();
                psh_hint_table_record(table, 2); // Already recorded, even when full.
                assert_eq!(core::slice::from_raw_parts(table, 80), snapshot);
            }
            capture::start();
            let snapshot = core::slice::from_raw_parts(table, 80).to_vec();
            psh_hint_table_record(table, u32::MAX);
            assert_eq!(core::slice::from_raw_parts(table, 80), snapshot);
            // Full-table failure still marks the hint and clears its stale link.
            *hints.add(18) = 0x80;
            *hints.add(19) = 0xdeadbeef;
            psh_hint_table_record(table, 2);
            assert_eq!(*hints.add(18), 0x84);
            assert_eq!(*hints.add(19), 0);
            assert_eq!(*table.add(1), 3);
            assert_eq!(*recorded.add(3), 0);
            let calls = capture::finish();
            assert_eq!(capture::formats(&calls), [
                "psh_hint_table_record: invalid hint index %d\n",
                "psh_hint_table_record: too many sorted hints!  BUG!\n",
            ]);
            assert_eq!(calls[0].args[0], u32::MAX);
            // Empty table reports invalid index without accessing its null pointers.
            *table = 0;
            *table.add(2) = 0;
            *table.add(4) = 0;
            psh_hint_table_record(table, 0);
        }
    }
}
