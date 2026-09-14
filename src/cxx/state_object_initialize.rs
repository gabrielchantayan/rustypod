//! `state_object_initialize` — original: `FUN_08076924` @ 0x08076924
//! (48 bytes true extent: 44 bytes of instructions plus its 4-byte literal
//! pool; the next separately linked function starts at 0x08076954).
//!
//! Decoding every ARM B/BL word in `osos.dec` finds six direct call sites,
//! all unconditional `bl` (0x0811f6b4, 0x0812c680, 0x0819c6c4,
//! 0x0819c710, 0x082282b4, and 0x082969ac); there are no predicated calls
//! or plain-`b` tail calls. The function initializes the 0x20-byte
//! state-machine base subobject: it records the descriptor and two incoming
//! initialization words, clears its three link words and terminal word, and
//! writes the initial `stop` state. No NULL or alignment guard is present in
//! stock. Deliberate deviations: none.

/// Initial FourCC state written to the base subobject's +0x18 word.
const STATE_OBJECT_STOPPED: u32 = 0x7374_6f70;

/// state_object_initialize — original: `FUN_08076924` @ 0x08076924 (48 bytes
/// true extent: 44 bytes of instructions plus a 4-byte literal pool; six
/// unconditional `bl` call sites, binary-scanned over all of `osos.dec`).
///
/// Initializes the eight 32-bit words of a state-machine base object. The
/// `initial_auxiliary` word is named only for its data flow: stock stores it
/// unchanged at +0x14, and its higher-level semantics are not identified.
/// Like the ARM `str` sequence, this requires a non-NULL, word-aligned
/// 0x20-byte writable object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn state_object_initialize(
    this: *mut u32,
    class_descriptor: u32,
    init_argument: u32,
    initial_auxiliary: u32,
) {
    this.add(3).write_volatile(class_descriptor);
    this.add(4).write_volatile(init_argument);
    this.add(5).write_volatile(initial_auxiliary);
    this.add(1).write_volatile(0);
    this.write_volatile(0);
    this.add(6).write_volatile(STATE_OBJECT_STOPPED);
    this.add(2).write_volatile(0);
    this.add(7).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_every_base_word_without_touching_neighbors() {
        let sentinel = 0xa5a5_5a5a;
        let mut words = [sentinel; 10];
        let base = unsafe { words.as_mut_ptr().add(1) };

        unsafe {
            state_object_initialize(base, 0x089c_b26c, 0xffff_ffff, 0x0123_4567);
        }

        assert_eq!(
            words,
            [
                sentinel,
                0,
                0,
                0,
                0x089c_b26c,
                0xffff_ffff,
                0x0123_4567,
                STATE_OBJECT_STOPPED,
                0,
                sentinel,
            ],
        );
    }

    #[test]
    fn overwrites_nonzero_base_state_with_zero_initialization_values() {
        let mut words = [u32::MAX; 8];

        unsafe {
            state_object_initialize(words.as_mut_ptr(), 0, 0, 0);
        }

        assert_eq!(words, [0, 0, 0, 0, 0, 0, STATE_OBJECT_STOPPED, 0]);
    }
}
