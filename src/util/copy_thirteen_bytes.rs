//! Fixed-width thirteen-byte copy helper.

/// copy_thirteen_bytes — original: `FUN_082231ac` @ **0x082231ac**.
/// **20 bytes**, five ARM instructions at `0x082231ac..0x082231c0`;
/// the next function starts at `0x082231c0`.
///
/// Raw words decode as `ldmia r1,{r2,r3,r12}`, `stmia r0,{r2,r3,r12}`,
/// `ldrb r1,[r1,#12]`, `strb r1,[r0,#12]`, `bx lr`. Load all three
/// words before storing any, then read and write byte 12, returning dst.
/// Full-image ARM BL decoding finds two unconditional inbound calls
/// (0x080fa494, 0x080fe098), zero predicated calls, and no outgoing calls.
/// Deliberate deviations: none; in particular, this is not snapshot memmove.
///
/// # Safety
/// Both pointers must be four-byte aligned and valid for thirteen bytes of
/// reads or writes, respectively. Overlap is permitted and follows the
/// grouped twelve-byte transfer followed by the final byte transfer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_thirteen_bytes(dst: *mut u8, src: *const u8) -> *mut u8 {
    let words = src.cast::<u32>();
    let first = words.read();
    let second = words.add(1).read();
    let third = words.add(2).read();
    let output = dst.cast::<u32>();
    output.write(first);
    output.add(1).write(second);
    output.add(2).write(third);
    dst.add(12).write(src.add(12).read());
    dst
}

#[cfg(test)]
mod tests {
    use super::copy_thirteen_bytes;

    #[repr(align(4))]
    struct AlignedBytes([u8; 48]);

    #[test]
    fn matches_grouped_transfer_for_disjoint_self_and_overlapping_ranges() {
        for src in (0..=32).step_by(4) {
            for dst in (0..=32).step_by(4) {
                let mut actual = AlignedBytes(core::array::from_fn(|i| (i * 37) as u8));
                let mut expected = actual.0;
                let mut snapshot = [0; 12];
                snapshot.copy_from_slice(&expected[src..src + 12]);
                expected[dst..dst + 12].copy_from_slice(&snapshot);
                expected[dst + 12] = expected[src + 12];
                let base = actual.0.as_mut_ptr();
                let returned = unsafe { copy_thirteen_bytes(base.add(dst), base.add(src)) };
                assert_eq!(returned, unsafe { base.add(dst) });
                assert_eq!(actual.0, expected, "src={src}, dst={dst}");
            }
        }
    }

    #[test]
    fn final_byte_is_read_after_word_stores() {
        let mut bytes = AlignedBytes(core::array::from_fn(|i| i as u8));
        let base = bytes.0.as_mut_ptr();
        unsafe { copy_thirteen_bytes(base.add(4), base) };
        assert_eq!(&bytes.0[4..16], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        assert_eq!(bytes.0[16], 8); // Source byte 12 was replaced by the third word.
        assert_eq!(&bytes.0[17..], &core::array::from_fn::<_, 48, _>(|i| i as u8)[17..]);
    }
}
