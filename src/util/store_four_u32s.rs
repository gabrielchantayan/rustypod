//! Stores four caller-supplied words into a contiguous record.

/// `store_four_u32s` — original: `FUN_082486e0` @ **0x082486e0** (12 bytes
/// exactly, `0x082486e0..0x082486ec`; the separately linked
/// [`crate::util::zero_four_words::zero_four_words`] begins at `0x082486ec`).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies seven direct inbound
/// call sites, all unconditional `bl` (0x0824c4ec, 0x0824c534, 0x0824c57c,
/// 0x082562f4, 0x08256344, 0x08256d14, and 0x0829f89c); there are no
/// predicated BL forms or direct tail branches. `ldr ip, [sp]` obtains the
/// fifth C-ABI argument, then `stm r0, {r1, r2, r3, ip}` stores all four
/// values at consecutive aligned words. `r0` remains unchanged and is the
/// return value, despite Ghidra declaring this function `void`.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `dst` must be non-NULL, four-byte aligned, and writable for four `u32`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.store_four_u32s")]
#[inline(never)]
pub unsafe extern "C" fn store_four_u32s(
    dst: *mut u32,
    first: u32,
    second: u32,
    third: u32,
    fourth: u32,
) -> *mut u32 {
    dst.write(first);
    dst.add(1).write(second);
    dst.add(2).write(third);
    dst.add(3).write(fourth);
    dst
}

#[cfg(test)]
mod tests {
    use super::store_four_u32s;

    #[test]
    fn stores_all_words_in_argument_order_and_returns_destination() {
        let mut words = [0xdead_beef, 0xcafe_babe, 0xfeed_face, 0x0123_4567];
        let dst = words.as_mut_ptr();

        let returned = unsafe {
            store_four_u32s(dst, 0, u32::MAX, 0x8000_0000, 0x7fff_ffff)
        };

        assert_eq!(returned, dst);
        assert_eq!(words, [0, u32::MAX, 0x8000_0000, 0x7fff_ffff]);
    }

    #[test]
    fn writes_exactly_four_words_at_an_interior_destination() {
        let mut words = [
            0x1111_1111,
            0x2222_2222,
            0x3333_3333,
            0x4444_4444,
            0x5555_5555,
            0x6666_6666,
        ];
        let dst = unsafe { words.as_mut_ptr().add(1) };

        unsafe {
            store_four_u32s(dst, 0x89ab_cdef, 0x7654_3210, 1, 0);
        }

        assert_eq!(
            words,
            [0x1111_1111, 0x89ab_cdef, 0x7654_3210, 1, 0, 0x6666_6666]
        );
    }
}
