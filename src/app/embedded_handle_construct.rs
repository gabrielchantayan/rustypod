//! Embedded handle constructor — FUN_081070a8 @ 0x081070a8.
//! True extent [0x081070a8, 0x081070b4): 12 bytes; the next function is
//! an independent BX LR. Raw words: e5801000 e5c02004 e12fff1e.
//! Two incoming plain BLs (0x0814a9fc, 0x082c8558), no predicated BLs;
//! no outgoing calls. Store the value word at +0 and the low tag byte
//! at +4, preserve padding +5..7, and return the unchanged handle pointer.
//! Deliberate deviations: none. The u32 tag retains the register ABI and
//! is truncated by the byte store. Ghidra's void return is incorrect.

/// Initialize an embedded handle without touching its trailing padding.
///
/// # Safety
/// `handle` must be aligned for u32 and writable for at least five bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn embedded_handle_construct(
    handle: *mut u32, value: u32, tag: u32,
) -> *mut u32 {
    handle.write(value);
    handle.add(1).cast::<u8>().write(tag as u8);
    handle
}

#[cfg(test)]
mod tests {
    use super::embedded_handle_construct;

    #[test]
    fn preserves_padding_neighbors_and_identity_while_truncating_tag() {
        for value in [0, 1, 0x8000_0000, u32::MAX] {
            for tag in [0, 1, 0xff, 0x100, 0x1234_5680, u32::MAX] {
                let mut words = [0xdead_beefu32, 0xa5a5_a5a5, 0x7654_3210, 0xcafe_babe];
                let handle = unsafe { words.as_mut_ptr().add(1) };
                assert_eq!(unsafe { embedded_handle_construct(handle, value, tag) }, handle);
                assert_eq!(words[0], 0xdead_beef);
                assert_eq!(words[1], value);
                let mut expected = 0x7654_3210u32.to_ne_bytes();
                expected[0] = tag as u8;
                assert_eq!(words[2].to_ne_bytes(), expected);
                assert_eq!(words[3], 0xcafe_babe);
            }
        }
    }
}
