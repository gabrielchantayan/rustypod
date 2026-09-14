//! `object_bytes_64_or_6c_nonzero` — original: `FUN_08131854` @
//! `0x08131854` (28 bytes).
//!
//! Raw `osos.dec` decoding establishes the full extent: the seven
//! instructions end with `bx lr` at `0x0813186c`, and the next function starts
//! at `0x08131870`. Decoding every ARM `B`/`BL` word finds **6 direct,
//! unconditional `bl` callers** (`0x08130a80`, `0x081314b8`, `0x08131f2c`,
//! `0x08132d14`, `0x08132d50`, and `0x08132e40`), with no predicated calls,
//! tail branches, or image data-word references.
//!
//! The routine reads the opaque object's byte at `+0x6c`. A nonzero value
//! returns one without reading `+0x64`; otherwise it returns whether the byte
//! at `+0x64` is nonzero. The caller corpus establishes that the result gates
//! waiting and follow-up operations, but not a concrete object type or field
//! meaning, so the offset-based name is deliberate.
//!
//! Deviation: none.

/// Returns whether either observed byte of an opaque application object is nonzero.
///
/// # Safety
///
/// `object` must point into a readable allocation that includes bytes `+0x64`
/// and `+0x6c`. The pointer may be unaligned because the retail routine uses
/// byte loads. When byte `+0x6c` is nonzero, byte `+0x64` need not be readable.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.object_bytes_64_or_6c_nonzero")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_bytes_64_or_6c_nonzero(object: *const u8) -> u32 {
    if object.add(0x6c).read() != 0 {
        1
    } else if object.add(0x64).read() != 0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTE_64_OFFSET: usize = 0x64;
    const BYTE_6C_OFFSET: usize = 0x6c;
    const GUARD: u8 = 0xa5;

    #[test]
    fn returns_boolean_or_of_both_observed_bytes() {
        let cases = [
            (0x00, 0x00, 0),
            (0x01, 0x00, 1),
            (0xff, 0x00, 1),
            (0x00, 0x01, 1),
            (0x00, 0xff, 1),
            (0x7e, 0x42, 1),
        ];
        let mut object = [GUARD; BYTE_6C_OFFSET + 2];

        for (byte_64, byte_6c, expected) in cases {
            object[BYTE_64_OFFSET] = byte_64;
            object[BYTE_6C_OFFSET] = byte_6c;
            let before = object;

            assert_eq!(unsafe { object_bytes_64_or_6c_nonzero(object.as_ptr()) }, expected,
                "byte_64={byte_64:#04x}, byte_6c={byte_6c:#04x}");
            assert_eq!(object, before, "the predicate must not mutate its object");
        }
    }

    #[test]
    fn accepts_an_unaligned_object_and_preserves_neighboring_bytes() {
        let mut storage = [GUARD; BYTE_6C_OFFSET + 4];
        let object = unsafe { storage.as_mut_ptr().add(1) };
        unsafe {
            object.add(BYTE_64_OFFSET).write(0);
            object.add(BYTE_6C_OFFSET).write(0x80);
        }
        let before = storage;

        assert_eq!(unsafe { object_bytes_64_or_6c_nonzero(object) }, 1);
        assert_eq!(storage, before, "the predicate must only read bytes");
        assert_eq!(storage[BYTE_64_OFFSET], GUARD, "byte before +0x64");
        assert_eq!(storage[BYTE_64_OFFSET + 2], GUARD, "byte after +0x64");
        assert_eq!(storage[BYTE_6C_OFFSET], GUARD, "byte before +0x6c");
        assert_eq!(storage[BYTE_6C_OFFSET + 2], GUARD, "byte after +0x6c");
    }
}
