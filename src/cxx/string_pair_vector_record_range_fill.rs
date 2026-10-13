//! Fill records — retailOS `FUN_083ea660` @ 0x083ea660.
//! True size: 56 bytes, extent 0x083ea660..0x083ea698; the next entry is PUSH.
//! Raw whole-image A32 decoding: one incoming plain BL at 0x083e1704 and
//! one outgoing plain BL at 0x083ea684, zero predicated BLs in either direction.
//!
//! Walk [first,end) in 20-byte steps. Leave the leading word intact, copy
//! source +4, then assign the vector at +8 through FUN_083e30f0. That callee
//! manages 12-byte entries containing two COW strings and a trailing word.
//! Re-read the source for each record; empty ranges touch neither operand.
//! Deliberate deviation: the unported vector assignment remains a firmware
//! seam, with its two actual pointer arguments (Ghidra's r2/r3 are scratch).
//! Fixed word layout avoids host pointer-width changes. Host tests exercise
//! the shared loop with a behavioral callee fixture, not firmware execution.

/// # Safety
/// `first..end` must delimit initialized, writable, aligned 20-byte records.
/// For a nonempty range `source` must remain a readable initialized record;
/// nested vectors must satisfy the retail vector assignment's requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_pair_vector_record_range_fill(
    first: *mut u32,
    end: *mut u32,
    source: *const u32,
) {
    let assign: unsafe extern "C" fn(*mut u32, *const u32) -> *mut u32 =
        core::mem::transmute(0x083e_30f0usize);
    fill_with(first, end, source, |destination, source| { assign(destination, source); });
}

#[inline(always)]
unsafe fn fill_with(
    mut first: *mut u32,
    end: *mut u32,
    source: *const u32,
    mut assign: impl FnMut(*mut u32, *const u32),
) {
    while first != end {
        first.add(1).write(source.add(1).read());
        assign(first.add(2), source.add(2));
        first = first.add(5);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_range_does_not_access_operands_or_assign() {
        unsafe {
            fill_with(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null(),
                |_, _| panic!("empty range must not assign"));
        }
    }

    #[test]
    fn preserves_prefix_and_excluded_records_and_observes_source_changes() {
        let mut records = [[0x11, 1, 2, 3, 4], [0x22, 5, 6, 7, 8],
            [0x33, 9, 10, 11, 12], [0x44, 13, 14, 15, 16]];
        let before = records;
        unsafe {
            let first = records.as_mut_ptr().cast::<u32>();
            let source = first.add(5);
            // The aliased source is itself in the fill range. A nested callee
            // can mutate its enclosing record; subsequent iterations must
            // observe that mutation rather than a snapshotted scalar.
            fill_with(first, first.add(15), source, |destination, nested_source| {
                let scalar = source.add(1).read();
                assert_eq!(destination.sub(1).read(), scalar);
                let value = nested_source.read();
                destination.write(value);
                source.add(1).write(scalar + 1);
            });
        }
        assert_eq!(records[0], [0x11, 5, 6, 3, 4]);
        assert_eq!(records[1], [0x22, 8, 6, 7, 8]);
        assert_eq!(records[2], [0x33, 7, 6, 11, 12]);
        assert_eq!(records[3], before[3]);
    }
}
