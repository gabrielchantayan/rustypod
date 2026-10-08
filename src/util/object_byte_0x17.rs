//! object_byte_0x17 — original: `FUN_081213fc` @ 0x081213fc (8 bytes;
//! two unconditional `bl` call sites, zero predicated `bl` call sites,
//! independently binary-scanned). The body contains no calls.
//!
//! Raw words 0xe5d00017 and 0xe12fff1e decode to `ldrb r0,[r0,#0x17]`
//! and `bx lr`; the next real function starts at 0x08121404 with a byte
//! store at offset 0x18. Returns the unsigned byte at object offset 0x17.
//! Caller 0x082832bc packs this byte into bits 8..15 of its result; the
//! concrete object type and field meaning remain unrecovered.
//!
//! Deliberate deviations: none. No null or bounds checks are introduced.

/// Returns the unsigned byte at offset 0x17 of `object`.
///
/// # Safety
/// `object.add(0x17)` must point to a readable, initialized byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_byte_0x17(object: *const u8) -> u8 {
    *object.add(0x17)
}

#[cfg(test)]
mod tests {
    use super::object_byte_0x17;

    #[test]
    fn returns_every_unsigned_byte_without_reading_neighbor_fields() {
        let mut object = [0x55u8; 0x19];
        object[0x16] = 0x12;
        object[0x18] = 0x34;
        for value in 0..=u8::MAX {
            object[0x17] = value;
            let before = object;
            assert_eq!(unsafe { object_byte_0x17(object.as_ptr()) } as u32, value as u32);
            assert_eq!(object, before);
        }
    }

    #[test]
    fn reads_byte_aligned_objects_at_each_word_alignment() {
        let mut storage = [0u8; 0x1b];
        for base in 0..4 {
            storage.fill(0x33);
            storage[base + 0x17] = 0x80 + base as u8;
            assert_eq!(unsafe { object_byte_0x17(storage.as_ptr().add(base)) },
                       0x80 + base as u8);
        }
    }
}
