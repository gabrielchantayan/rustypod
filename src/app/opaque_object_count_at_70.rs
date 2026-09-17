//! `opaque_object_count_at_70` — original: `FUN_08298afc` @ `0x08298afc`
//! (8 bytes).
//!
//! Raw `osos.dec` words decode as `ldr r0,[r0,#0x70]; bx lr` at
//! `0x08298afc..0x08298b00`; the independently linked next function starts
//! at `0x08298b04`. Complete aligned ARM B/BL-immediate decoding finds four
//! inbound direct calls, all plain unconditional `bl` at `0x081b23e0`,
//! `0x081b26b0`, `0x0829d550`, and `0x0829d730`; there are no predicated
//! `bl` calls. Callers use the returned word as an upper bound while
//! enumerating a collection-like object.
//!
//! The concrete object and count unit remain unrecovered. Deliberate
//! deviation: LLVM emits a standard frame prologue/epilogue around the same
//! unchecked aligned load; there is no NULL, bounds, ownership, or range
//! validation.

/// Byte offset of the opaque object's collection-count word.
const COUNT_OFFSET: usize = 0x70;

/// Returns the opaque object's collection-count word at `+0x70` unchanged.
///
/// # Safety
///
/// `object` must be non-NULL, four-byte aligned, and readable through its
/// 32-bit field at `+0x70`; these are precisely the ARM `ldr` preconditions.
#[cfg_attr(target_os = "none", link_section = ".text.opaque_object_count_at_70")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_object_count_at_70(object: *const u8) -> u32 {
    unsafe { (object.add(COUNT_OFFSET) as *const u32).read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT_WORDS: usize = (COUNT_OFFSET / core::mem::size_of::<u32>()) + 1;
    const COUNT_WORD_INDEX: usize = COUNT_OFFSET / core::mem::size_of::<u32>();
    const SENTINEL: u32 = 0xa5a5_a5a5;

    fn with_count(count: u32) -> [u32; OBJECT_WORDS] {
        let mut object = [SENTINEL; OBJECT_WORDS];
        object[COUNT_WORD_INDEX] = count;
        object
    }

    #[test]
    fn returns_zero_and_nonzero_count_representations_unchanged() {
        for count in [0, 1, 0x8000_0000, u32::MAX] {
            let object = with_count(count);

            assert_eq!(unsafe { opaque_object_count_at_70(object.as_ptr().cast()) }, count);
        }
    }

    #[test]
    fn reads_only_the_count_word() {
        let object = with_count(0x1234_5678);
        let before = object;

        assert_eq!(unsafe { opaque_object_count_at_70(object.as_ptr().cast()) }, 0x1234_5678);
        assert_eq!(object, before, "accessor must not write the object");
    }
}
