//! `reverse_byte_cursor_pop` — original: `FUN_08268090` @ load address
//! **0x08268090**.
//!
//! Raw ARM words establish the true 36-byte extent, 0x08268090..0x082680b0:
//! `bx lr` at 0x082680b0 is followed by a separate, structurally identical
//! cursor operation at 0x082680b4. The assigned body has two known direct
//! plain-BL callers in recovered C and no outgoing calls; no callee seam is
//! required.
//!
//! It returns zero for an empty half-open byte range at target words +0x08 and
//! +0x0c. Otherwise it decrements the end word, stores it, and returns the
//! byte at the decremented address.
//!
//! # Deliberate deviations
//!
//! The target-width pointer fields remain raw `u32` words rather than host
//! pointers, so their offsets are invariant on 64-bit host tests.

/// Pops one byte from the end of a target-width half-open byte range.
///
/// Original: `FUN_08268090` @ 0x08268090 (36 bytes; 2 known unconditional
/// plain-BL call sites, zero known predicated BL call sites).
///
/// # Safety
///
/// `cursor` must name four aligned, readable target words. When word +0x0c
/// differs from word +0x08, its decremented target address must be readable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn reverse_byte_cursor_pop(cursor: *mut u8) -> u8 {
    let words = cursor.cast::<u32>();
    let end = words.add(3).read();
    if words.add(2).read() == end {
        return 0;
    }

    let previous = end - 1;
    let byte = (previous as usize as *const u8).read();
    words.add(3).write(previous);
    byte
}

#[cfg(test)]
static REVERSE_BYTE_CURSOR_POP_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());


#[cfg(test)]
mod tests {
    use super::{reverse_byte_cursor_pop, REVERSE_BYTE_CURSOR_POP_TEST_LOCK};
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn returns_zero_without_changing_an_empty_range() {
        let _lock = REVERSE_BYTE_CURSOR_POP_TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::REVERSE_BYTE_CURSOR_POP, 32) else {
            return;
        };
        unsafe {
            let words = slab.cast::<u32>();
            words.add(2).write((slab.add(16)) as usize as u32);
            words.add(3).write((slab.add(16)) as usize as u32);
            assert_eq!(reverse_byte_cursor_pop(slab), 0);
            assert_eq!(words.add(3).read(), (slab.add(16)) as usize as u32);
        }
    }

    #[test]
    fn pops_in_reverse_order_and_updates_only_end() {
        let _lock = REVERSE_BYTE_CURSOR_POP_TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::REVERSE_BYTE_CURSOR_POP, 32) else {
            return;
        };
        unsafe {
            let bytes = slab.add(16);
            bytes.add(0).write(0x17);
            bytes.add(1).write(0x42);
            bytes.add(2).write(0xfe);
            let words = slab.cast::<u32>();
            words.add(2).write(bytes as usize as u32);
            words.add(3).write(bytes.add(3) as usize as u32);

            assert_eq!(reverse_byte_cursor_pop(slab), 0xfe);
            assert_eq!(words.add(3).read(), bytes.add(2) as usize as u32);
            assert_eq!(reverse_byte_cursor_pop(slab), 0x42);
            assert_eq!(reverse_byte_cursor_pop(slab), 0x17);
            assert_eq!(reverse_byte_cursor_pop(slab), 0);
            assert_eq!(words.add(2).read(), bytes as usize as u32);
        }
    }
}
