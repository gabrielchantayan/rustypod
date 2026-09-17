//! Copy construction for the 37-word deque-related layout used by retailOS.

use super::templates::deque_iter_assign_alias_c774;
use crate::libc::memcpy::memcpy_forward_words;

/// deque_layout_copy_construct — original: `FUN_0824cccc` @ `0x0824cccc`
/// (192 bytes, `0x0824cccc..0x0824cd8c`; four inbound plain-`bl` call sites;
/// three unconditional internal `bl` instructions and no predicated `bl`,
/// binary-verified).
///
/// The copy constructor first copies two 16-byte deque iterators, then copies
/// seven scalar words and three more 16-byte iterator-like groups. It invokes
/// the IRAM `memcpy` veneer for the nine words at +0x6c, then transfers only
/// bits 0..7 of the final +0x90 control word, preserving destination bits
/// 8..31. The next independently linked function begins with `mov r3,r0` at
/// `0x0824cd8c`.
///
/// Deliberate deviation: the retail veneer at `0x08037df8` is represented by
/// the already ported [`memcpy_forward_words`] body; this preserves its
/// aligned forward-copy behavior without creating a duplicate veneer seam.
///
/// # Safety
///
/// `dst` and `src` must be valid, four-byte aligned pointers to 37-word
/// layouts. As in retailOS, overlapping ranges follow the ordered forward
/// reads and writes and are not made overlap-safe.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_layout_copy_construct")]
#[inline(never)]
pub unsafe extern "C" fn deque_layout_copy_construct(
    dst: *mut u32,
    src: *const u32,
) -> *mut u32 {
    deque_iter_assign_alias_c774(dst, src);
    deque_iter_assign_alias_c774(dst.add(4), src.add(4));

    let (word8, word9, word10, word11) = (
        src.add(8).read(),
        src.add(9).read(),
        src.add(10).read(),
        src.add(11).read(),
    );
    dst.add(8).write(word8);
    dst.add(9).write(word9);
    dst.add(10).write(word10);
    dst.add(11).write(word11);
    dst.add(12).write(src.add(12).read());
    dst.add(13).write(src.add(13).read());
    dst.add(14).write(src.add(14).read());

    for group in 0..3 {
        let src_group = src.add(15 + group * 4);
        let dst_group = dst.add(15 + group * 4);
        let (word0, word1, word2, word3) = (
            src_group.read(),
            src_group.add(1).read(),
            src_group.add(2).read(),
            src_group.add(3).read(),
        );
        dst_group.write(word0);
        dst_group.add(2).write(word2);
        dst_group.add(1).write(word1);
        dst_group.add(3).write(word3);
    }

    memcpy_forward_words(dst.add(27).cast(), src.add(27).cast(), 0x24);

    let dst_flags = dst.add(36);
    let first_flags = (dst_flags.read_volatile() & !3) | (src.add(36).read_volatile() & 3);
    dst_flags.write_volatile(first_flags);
    let final_flags = (first_flags & !0xfc) | (src.add(36).read_volatile() & 0xfc);
    dst_flags.write_volatile(final_flags);
    dst
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_every_field_but_the_preserved_flag_bits() {
        let src: [u32; 37] = core::array::from_fn(|word| 0x1020_3000u32.wrapping_add(word as u32 * 0x0101));
        let mut dst = [0xdead_beefu32; 37];
        dst[36] = 0xa5a5_5a00;

        let returned = unsafe { deque_layout_copy_construct(dst.as_mut_ptr(), src.as_ptr()) };

        assert_eq!(returned, dst.as_mut_ptr());
        assert_eq!(&dst[..36], &src[..36]);
        assert_eq!(dst[36], 0xa5a5_5a00 | (src[36] & 0xff));
    }

    #[test]
    fn leaves_high_control_bits_at_destination() {
        let mut src = [0u32; 37];
        let mut dst = [0xffff_ffffu32; 37];
        src[36] = 0x1234_5678;

        unsafe { deque_layout_copy_construct(dst.as_mut_ptr(), src.as_ptr()) };

        assert_eq!(dst[36], 0xffff_ff78);
    }
}
