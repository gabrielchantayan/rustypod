//! Raw object-state byte predicates ported from retailOS.

/// object_byte2_is_nonzero — original: `FUN_080395d8` @ `0x080395d8`
/// (16 bytes; source: `ipod-decomp/decomp/c/002/080395d8_FUN_080395d8.c`).
///
/// Reads exactly the byte at `object + 0x02` and returns the ARM boolean ABI
/// value: 0 when it is zero, otherwise 1. The four-instruction ARM leaf is
/// `ldrb r0,[r0,#2]; cmp r0,#0; movne r0,#1; bx lr`; neither the object's
/// concrete type nor the field's meaning has been recovered. The sole
/// recovered direct caller, `0x080a55ec`, records this result into its output
/// record at `+0x14` while parsing a 16-byte input record.
///
/// # Safety
///
/// `object` must designate at least three readable bytes. It is not
/// null-checked, matching the original `ldrb`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_byte2_is_nonzero(object: *const u8) -> u32 {
    u32::from(object.add(2).read_volatile() != 0)
}

/// object_byte_at_8 — original: `FUN_0829d0b4` @ `0x0829d0b4`
/// (8 bytes; 11 verified direct `bl` call sites, all unconditional).
///
/// Loads and returns the raw unsigned byte at `object + 0x08`. Raw
/// disassembly is `ldrb r0,[r0,#8]; bx lr`; the binary-wide ARM B/BL scan
/// found calls at 0x081ef5fc, 0x08202774, 0x08277a0c, 0x08277ac8,
/// 0x08277c10, 0x0827826c, 0x0827850c, 0x082787e0, 0x08278d40,
/// 0x082a53b8, and 0x082a5434, with no predicated call or DATA-word
/// reference. Callers use the byte as a state/error gate after acquiring a
/// counted mutex, but establish neither the concrete object type nor the
/// field's domain meaning. The offset-based name intentionally preserves
/// only the verified behavior.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `object` must designate at least nine readable bytes. It is not
/// null-checked, matching the original byte load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_byte_at_8(object: *const u8) -> u8 {
    object.add(8).read()
}

/// object_dispatch_code_at_8 — original: `FUN_0829f184` @ `0x0829f184`
/// (12 bytes; 10 verified direct `bl` call sites, all unconditional).
///
/// Loads the aligned 32-bit word at `object + 0x08` and returns its low byte
/// zero-extended as a dispatch code. Raw ARM is
/// `ldr r0,[r0,#8]; and r0,r0,#0xff; bx lr`; the next separately linked
/// function begins at `0x0829f190`. Callers compare the result against action
/// codes 6 through 10, but do not establish a concrete object type.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `object` must be non-null, 4-byte aligned, and designate a readable word
/// at byte offset `0x08`, matching the original aligned word load.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_dispatch_code_at_8(object: *const u8) -> u32 {
    core::ptr::read_volatile(object.add(8) as *const u32) & 0xff
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn returns_arm_boolean_for_zero_and_nonzero_byte2_values() {
        for (byte2, expected) in [(0u8, 0u32), (1, 1), (0x80, 1), (u8::MAX, 1)] {
            let object = [0xa5, 0x5a, byte2];
            assert_eq!(unsafe { object_byte2_is_nonzero(object.as_ptr()) }, expected);
        }
    }

    #[test]
    fn reads_only_the_byte_at_target_offset_without_writing() {
        let mut storage = [0xd1, 0xa5, 0x5a, 0, 0xc3, 0xe7, 0xb4];
        let before = storage;
        let object = unsafe { storage.as_ptr().add(1) };

        assert_eq!(unsafe { object_byte2_is_nonzero(object) }, 0);
        storage[3] = 0x01;
        assert_eq!(unsafe { object_byte2_is_nonzero(object) }, 1);

        assert_eq!(storage[0], before[0]);
        assert_eq!(storage[1], before[1]);
        assert_eq!(storage[2], before[2]);
        assert_eq!(storage[4], before[4]);
        assert_eq!(storage[5], before[5]);
        assert_eq!(storage[6], before[6]);
    }

    #[test]
    fn returns_every_byte_value_at_offset_eight_without_mutating_object() {
        let mut object = [0xa5u8; 10];

        for value in 0u8..=u8::MAX {
            object[8] = value;
            let before = object;

            assert_eq!(unsafe { object_byte_at_8(object.as_ptr()) }, value, "byte={value:#04x}");
            assert_eq!(object, before, "read changed object for byte={value:#04x}");
        }
    }

    #[test]
    fn ignores_every_other_byte_of_a_minimally_sized_object() {
        let mut object = [0x5au8; 9];
        object[8] = 0xc3;

        for offset in 0..8 {
            for replacement in [0u8, 0xff] {
                object[offset] = replacement;
                assert_eq!(unsafe { object_byte_at_8(object.as_ptr()) }, 0xc3, "object +{offset:#x} = {replacement:#04x}");
            }
            object[offset] = 0x5a;
        }
    }
    #[test]
    fn reads_the_low_byte_of_the_aligned_word_at_offset_eight() {
        #[repr(C)]
        struct ObjectWords {
            word_0: u32,
            word_4: u32,
            dispatch_word: u32,
        }

        let mut object = ObjectWords {
            word_0: 0x0123_4567,
            word_4: 0x89ab_cdef,
            dispatch_word: 0,
        };
        for word in [0x0000_0000u32, 0xffff_ffff, 0x1234_5606, 0x7fff_ff07, 0x8000_0009, 0xdead_be0a] {
            object.dispatch_word = word;
            let before = [object.word_0, object.word_4, object.dispatch_word];

            assert_eq!(unsafe { object_dispatch_code_at_8((&object as *const ObjectWords).cast()) }, word & 0xff);
            assert_eq!(
                [object.word_0, object.word_4, object.dispatch_word],
                before,
                "the word accessor is read-only"
            );
        }
    }
}
