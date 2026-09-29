//! Fixed-width text copy with space padding — `FUN_082e04d0` @ 0x082e04d0.
//!
//! Raw `osos.dec` establishes the exact 44-byte extent 0x082e04d0..0x082e04fb:
//! `bx lr` ends the routine and the following `push {r4,lr}` starts the next
//! independent function. Whole-image ARM decoding finds two inbound plain BL
//! calls at 0x082e2694 and 0x082e26a4, zero inbound predicated BL calls, and
//! no outbound calls. The routine copies at most `len` source bytes into the
//! destination; after the first NUL it writes spaces for the remaining width
//! without advancing or reading the source pointer. Deliberate deviation: none.

/// Copies a fixed-width text field, replacing its NUL terminator and all
/// remaining destination bytes with spaces.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn copy_text_padded_with_spaces(
    destination: *mut u8,
    source: *const u8,
    len: u32,
) {
    let mut destination = destination;
    let mut source = source;
    let mut remaining = len;
    loop {
        let (next_remaining, underflowed) = remaining.overflowing_sub(1);
        remaining = next_remaining;
        if underflowed {
            break;
        }

        let byte = source.read_volatile();
        if byte == 0 {
            destination.write_volatile(b' ');
        } else {
            destination.write_volatile(byte);
            source = source.add(1);
        }
        destination = destination.add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_full_width_source() {
        let source = *b"ABCDEFGH";
        let mut destination = [0xa5; 8];

        unsafe { copy_text_padded_with_spaces(destination.as_mut_ptr(), source.as_ptr(), 8) };

        assert_eq!(destination, source);
    }

    #[test]
    fn pads_remaining_width_after_first_nul_without_reading_past_it() {
        let source = [b'A', 0];
        let mut destination = [0xa5; 8];

        unsafe { copy_text_padded_with_spaces(destination.as_mut_ptr(), source.as_ptr(), 8) };

        assert_eq!(destination, *b"A       ");
    }

    #[test]
    fn zero_length_leaves_destination_untouched() {
        let mut destination = [0xa5; 3];

        unsafe { copy_text_padded_with_spaces(destination.as_mut_ptr(), core::ptr::null(), 0) };

        assert_eq!(destination, [0xa5; 3]);
    }
}
