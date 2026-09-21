//! Tests whether a word key falls inside a half-open word range.

/// `half_open_word_range_contains` — original: `FUN_08297638` @ `0x08297638`
/// (32 bytes; source: `ipod-decomp/decomp/c/028/08297638_FUN_08297638.c`).
///
/// Raw `osos.dec` words establish the complete eight-instruction body from
/// `0x08297638` through `0x08297654`; `mov r0,#0x6600` at `0x08297658` starts
/// the next independently linked function. It has no outgoing calls. Raw
/// caller decoding finds three inbound plain `bl` calls (0x08127328,
/// 0x081dc554, and 0x081dc58c) and zero predicated `bl` calls.
///
/// Reads the key and the range's two aligned u32 bounds, returning one exactly
/// when `start <= key < end` under ARM unsigned comparison; otherwise returns
/// zero. The end bound is exclusive, including when both bounds are equal.
///
/// Deliberate deviations: none.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn half_open_word_range_contains(range: *const u32, key: *const u32) -> u32 {
    let key = unsafe { *key };
    let start = unsafe { *range };
    let end = unsafe { *range.add(1) };
    (start <= key && key < end) as u32
}

#[cfg(test)]
mod tests {
    use super::half_open_word_range_contains;

    #[test]
    fn accepts_start_and_interior_but_not_exclusive_end() {
        let range = [10, 20];
        for (key, expected) in [(9, 0), (10, 1), (19, 1), (20, 0), (21, 0)] {
            assert_eq!(unsafe { half_open_word_range_contains(range.as_ptr(), &key) }, expected);
        }
    }

    #[test]
    fn empty_and_unsigned_high_ranges_follow_arm_comparisons() {
        let empty = [0x8000_0000, 0x8000_0000];
        let high = [0xffff_fffe, u32::MAX];
        for (range, key, expected) in [
            (empty, 0x8000_0000, 0),
            (high, 0x7fff_ffff, 0),
            (high, 0xffff_fffe, 1),
            (high, u32::MAX, 0),
        ] {
            assert_eq!(unsafe { half_open_word_range_contains(range.as_ptr(), &key) }, expected);
        }
    }
}
