//! Tagged link encoding — `FUN_080d7f24` at `0x080d7f24`, 96 bytes
//! (`0x080d7f24..0x080d7f84`, next real function at `0x080d7f84`).
//!
//! Raw A32 words verify two plain outbound BLs, no predicated BLs, and two
//! plain inbound BLs at `0x08099b50` and `0x080e4ae4` (no predicated callers).
//! Read the indexed base once, then refresh the selected span up to three
//! times. An address in the unsigned half-open span becomes `(address-base)|2`;
//! otherwise return `address|1`. Add/subtract wrap at 32 bits. Incoming r2/r3
//! seed the span and survive lookups that reject selectors greater than three.
//!
//! Deliberate deviations: inline the verified six-instruction base getter at
//! `0x080d7f84`, using the existing indexed table seam. The span lookup remains
//! the resident `0x080b64fc` call; its identity is not independently named in
//! names.yaml. Host builds replace only that call. No behavioral deviations.

use crate::util::indexed_state_set_and_poll::indexed_state_table;

pub type SpanLookup = unsafe extern "C" fn(u32, u32, *mut u32) -> u32;

#[cfg(not(target_os = "none"))]
pub static mut INDEXED_SPAN_LOOKUP: Option<SpanLookup> = None;

#[inline(always)]
unsafe fn refresh_span(selector: u32, span: *mut u32) {
    #[cfg(target_os = "none")]
    let lookup: SpanLookup = core::mem::transmute(0x080b_64fcusize);
    #[cfg(not(target_os = "none"))]
    let lookup = core::ptr::addr_of!(INDEXED_SPAN_LOOKUP).read_volatile()
        .expect("indexed span lookup must be installed on host");
    let _ = lookup(selector, selector, span);
}

/// Encode a raw address as a tagged indexed-base-relative or absolute link.
///
/// # Safety
/// The table must be readable at the signed low-halfword selector's 99-word
/// record, including word one. The resident lookup must be callable and its
/// indexed object valid. Host callers must install INDEXED_SPAN_LOOKUP.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_span_encode_link(
    selector: u32, address: u32, initial_start: u32, initial_len: u32,
) -> u32 {
    let base = indexed_state_table()
        .offset(selector as i16 as isize * 99 + 1).read_volatile();
    let mut span = [initial_start, initial_len];
    for _ in 0..3 {
        refresh_span(selector, span.as_mut_ptr());
        if span[0] <= address && address < span[0].wrapping_add(span[1]) {
            return address.wrapping_sub(base) | 2;
        }
    }
    address | 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::indexed_state_set_and_poll::{INDEXED_STATE_TABLE, INDEXED_STATE_TABLE_TEST_LOCK};

    static mut SPANS: [[u32; 2]; 3] = [[0; 2]; 3];
    static mut CALLS: usize = 0;
    unsafe extern "C" fn lookup(_: u32, selector: u32, out: *mut u32) -> u32 {
        let call = CALLS;
        CALLS += 1;
        if selector > 3 { return 0xffff_ff05; }
        out.write(SPANS[call][0]);
        out.add(1).write(SPANS[call][1]);
        0
    }

    unsafe fn check(selector: u32, address: u32, seed: [u32; 2], spans: [[u32; 2]; 3], base: u32, expected: u32, calls: usize) {
        let mut table = [0u32; 699];
        // Center allows negative low-halfword selectors without host pointers
        // ever being stored in target-width words.
        let center = table.as_mut_ptr().add(199);
        center.offset(selector as i16 as isize * 99 + 1).write(base);
        let saved_table = INDEXED_STATE_TABLE;
        let saved_lookup = INDEXED_SPAN_LOOKUP;
        INDEXED_STATE_TABLE = center;
        INDEXED_SPAN_LOOKUP = Some(lookup);
        SPANS = spans;
        CALLS = 0;
        let result = indexed_span_encode_link(selector, address, seed[0], seed[1]);
        let actual_calls = CALLS;
        INDEXED_STATE_TABLE = saved_table;
        INDEXED_SPAN_LOOKUP = saved_lookup;
        assert_eq!(result, expected);
        assert_eq!(actual_calls, calls);
    }

    #[test]
    fn half_open_bounds_zero_length_and_wrapping_end() {
        let _guard = INDEXED_STATE_TABLE_TEST_LOCK.lock();
        unsafe {
            for (address, expected, calls) in [(99, 99, 3), (100, 22, 1), (119, 39, 1), (120, 121, 3)] {
                check(0, address, [0; 2], [[100, 20]; 3], 80, expected, calls);
            }
            check(1, 100, [0; 2], [[100, 0]; 3], 80, 101, 3);
            check(2, 0xffff_fff0, [0; 2], [[0xffff_ffe0, 64]; 3], 80, 0xffff_fff1, 3);
            check(3, 100, [0; 2], [[100, 20]; 3], 120, 0xffff_ffee, 1);
        }
    }

    #[test]
    fn retries_refresh_span_and_preserves_rejected_lookup_seed() {
        let _guard = INDEXED_STATE_TABLE_TEST_LOCK.lock();
        unsafe {
            check(0, 104, [0; 2], [[200, 20], [100, 20], [0, 0]], 80, 26, 2);
            check(0, 104, [0; 2], [[200, 20], [0, 0], [100, 20]], 80, 26, 3);
            check(4, 104, [100, 20], [[0; 2]; 3], 80, 26, 1);
            check(0xffff_ffff, 104, [100, 20], [[0; 2]; 3], 80, 26, 1);
            check(0x0001_0000, 104, [0, 0], [[100, 20]; 3], 80, 105, 3);
        }
    }
}
