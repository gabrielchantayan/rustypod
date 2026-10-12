//! Capped append of counted UTF-16 strings.
//!
//! Original: `FUN_0803c5e8` @ `0x0803c5e8`, 76 bytes through
//! `0x0803c634` (the next function starts with `ldr r0, [r0, #0xf00]`).
//! Raw ARM word scan: two unconditional inbound BL at 0x08058d2c and
//! 0x08058d3c, zero predicated BL; zero outbound BL. The `bls` at
//! 0x0803c628 is a conditional B (unsigned lower-or-same), not a BL.
//!
//! If both pointers are non-NULL, sum their u16 counts in u32, cap the
//! result, and copy source payload forward after the old destination end.
//! Store the resulting count as u16 even when the cap shrinks the old
//! destination count (no copying), or the sum exceeds u16::MAX (truncate).
//! No terminator is written. The insertion caller at 0x08058cc4 uses
//! two appends with cap 255 to join an insertion and a saved suffix.
//!
//! Deliberate deviations: volatile halfword accesses preserve overlapping
//! forward-copy semantics and prevent LLVM from replacing the loop with
//! memcpy. Valid Rust objects cannot straddle the target address-space
//! wraparound; otherwise the algorithm and count truncation are unchanged.

/// Append `source` to `destination`, both count-prefixed u16 buffers.
///
/// # Safety
/// Non-NULL operands must have aligned, readable count words. If both are
/// non-NULL, destination must be writable for its count and the appended
/// payload; source must be readable for the copied payload. Overlap is
/// allowed: each halfword is read immediately before its forward write.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn counted_wstr_append(
    source: *const u16,
    destination: *mut u16,
    max_len: u32,
) {
    if source.is_null() || destination.is_null() {
        return;
    }
    let source_len = source.read_volatile() as u32;
    let old_len = destination.read_volatile() as u32;
    let new_len = (source_len + old_len).min(max_len);
    let mut destination_index = old_len + 1;
    let mut source_index = 1;
    while destination_index <= new_len {
        let value = source.add(source_index).read_volatile();
        destination.add(destination_index as usize).write_volatile(value);
        source_index += 1;
        destination_index += 1;
    }
    destination.write_volatile(new_len as u16);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_empty_payloads_and_untouched_tails() {
        for source_len in 0..=8usize {
            for old_len in 0..=8usize {
                for cap in 0..=18u32 {
                    let mut source = [0u16; 9];
                    source[0] = source_len as u16;
                    for i in 1..=8 { source[i] = 0x8000 + i as u16; }
                    let mut destination = [0xdead; 20];
                    destination[0] = old_len as u16;
                    let mut expected = destination;
                    let end = (source_len + old_len).min(cap as usize);
                    if end > old_len {
                        expected[old_len + 1..=end]
                            .copy_from_slice(&source[1..=end - old_len]);
                    }
                    expected[0] = end as u16;
                    unsafe { counted_wstr_append(source.as_ptr(), destination.as_mut_ptr(), cap); }
                    assert_eq!(destination, expected);
                }
            }
        }
    }

    #[test]
    fn null_operand_does_not_access_other_operand() {
        let mut destination = [2, 0x41, 0x42, 0xbeef];
        unsafe {
            counted_wstr_append(core::ptr::null(), destination.as_mut_ptr(), 0);
            counted_wstr_append(core::ptr::null(), core::ptr::null_mut(), 0);
            counted_wstr_append(core::ptr::NonNull::<u16>::dangling().as_ptr(), core::ptr::null_mut(), 9);
        }
        assert_eq!(destination, [2, 0x41, 0x42, 0xbeef]);
    }

    #[test]
    fn self_append_and_forward_overlap() {
        let mut same = [3, 0x41, 0, 0xd800, 0xffff, 0xffff, 0xffff, 0xbeef];
        unsafe { counted_wstr_append(same.as_ptr(), same.as_mut_ptr(), 6); }
        assert_eq!(same, [6, 0x41, 0, 0xd800, 0x41, 0, 0xd800, 0xbeef]);

        // Destination payload overwrites future source elements: not memmove.
        let mut overlapping = [4, 1, 0x41, 0x42, 0x43, 0x44, 0xbeef];
        unsafe {
            let base = overlapping.as_mut_ptr();
            counted_wstr_append(base, base.add(1), 5);
        }
        assert_eq!(overlapping, [4, 5, 0x41, 1, 0x41, 1, 0x41]);
    }

    #[test]
    fn count_sum_is_wide_then_truncated() {
        extern crate std;
        let source = [1, 0xcafe];
        let mut destination = std::vec![0x1234u16; 65538];
        destination[0] = u16::MAX;
        unsafe { counted_wstr_append(source.as_ptr(), destination.as_mut_ptr(), u32::MAX); }
        assert_eq!(destination[0], 0);
        assert_eq!(destination[65535], 0x1234);
        assert_eq!(destination[65536], 0xcafe);
        assert_eq!(destination[65537], 0x1234);
    }
}
