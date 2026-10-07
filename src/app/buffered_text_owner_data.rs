//! Buffered text data address — `FUN_0815236c` @ `0x0815236c`.
//!
//! True extent [0x0815236c, 0x08152374): 8 bytes. Raw A32 words are
//! `e5900010` (ldr r0, [r0, #16]) and `e12fff1e` (bx lr); the next
//! function begins with a register-save prologue at 0x08152374.
//! Whole-image aligned A32 decoding verifies two incoming plain BLs
//! (0x080fdcc4, 0x08293618), zero predicated incoming BLs and zero
//! outgoing plain or predicated BLs.
//!
//! Return the embedded text buffer's data-address word at owner +16.
//! Callers use it as the source for chunked text copies; construction
//! initializes it at embedded text +4 (owner +12 +4). No behavioral
//! deviations: retain the ARM-width address as u32, including on hosts,
//! without dereferencing it or validating NULL.

/// # Safety
/// `owner` must permit an aligned four-byte read at byte offset 16.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffered_text_owner_data(owner: *const u8) -> u32 {
    owner.cast::<u32>().add(4).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_full_address_word_without_reading_pointee_or_mutating_owner() {
        for address in [0, 1, 0x0800_0000, 0x089c_c96c, 0x8000_0000, u32::MAX] {
            let owner = [0xa5a5_a5a5, 0x1111_1111, 0x2222_2222, 0x3333_3333, address];
            let before = owner;
            let bytes = unsafe {
                core::slice::from_raw_parts(owner.as_ptr().cast::<u8>(), 20)
            };
            let reference = u32::from_ne_bytes(bytes[16..20].try_into().unwrap());
            assert_eq!(unsafe { buffered_text_owner_data(owner.as_ptr().cast()) }, reference);
            assert_eq!(owner, before);
        }
    }

    #[test]
    fn reads_relative_to_receiver_not_slab_start() {
        let slab = [0xdead_beefu32, 7, 8, 9, 10, 0xf123_4567, 0xfeed_face];
        assert_eq!(unsafe {
            buffered_text_owner_data(slab.as_ptr().add(1).cast())
        }, 0xf123_4567);
    }
}
