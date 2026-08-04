//! Accessor for an unidentified UI object's state word.

/// object_state_word — original: `FUN_08055e80` @ `0x08055e80` (12 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055e80_FUN_08055e80.c`.
/// The ARM leaf loads and returns the little-endian 32-bit state word at
/// offset `0xe38` in an otherwise unidentified UI object. It performs no
/// null or alignment checks, matching the original `ldr` ABI.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_state_word(object: *const u8) -> u32 {
    (object.add(0xe38) as *const u32).read()
}

/// The UI sequence identifier state (original global @ `0x089c_fcc4`).
///
/// The firmware reaches this runtime-initialized word through the literal at
/// `0x0805_5ecc`; this static models that target-side state.
pub static mut SEQUENCE_ID: u32 = 0;

/// sequence_id_next — original: `FUN_08055eb8` @ `0x08055eb8` (16 bytes).
///
/// Sources: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055eb8_FUN_08055eb8.c`
/// and `decomp/osos.asm` @ `0x08055eb8..0x08055ec8`. The decompilation
/// incorrectly declares `void`; the ARM leaf leaves the loaded word in `r0`.
/// It loads the sequence word at `0x089c_fcc4` through its `0x0805_5ecc`
/// literal, stores that word plus one with wrapping 32-bit arithmetic, and
/// returns the pre-increment value. The runtime global is modeled by
/// [`SEQUENCE_ID`] rather than its fixed device address.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sequence_id_next() -> u32 {
    let state = core::ptr::addr_of_mut!(SEQUENCE_ID);
    let sequence_id = core::ptr::read_volatile(state);
    core::ptr::write_volatile(state, sequence_id.wrapping_add(1));
    sequence_id
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use std::sync::Mutex;

    static SEQUENCE_ID_LOCK: Mutex<()> = Mutex::new(());

    fn seed_sequence_id(value: u32) {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SEQUENCE_ID), value);
        }
    }

    fn sequence_id() -> u32 {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SEQUENCE_ID)) }
    }

    #[test]
    fn returns_the_word_at_offset_e38() {
        let mut object = [0u8; 0xe3c];
        object[0xe38..0xe3c].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());

        assert_eq!(unsafe { object_state_word(object.as_ptr()) }, 0x89ab_cdef);
    }

    #[test]
    fn ignores_adjacent_object_bytes() {
        let mut object = [0xa5u8; 0xe40];
        object[0xe34..0xe38].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        object[0xe38..0xe3c].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        object[0xe3c..0xe40].copy_from_slice(&0x99aa_bbccu32.to_le_bytes());

        assert_eq!(unsafe { object_state_word(object.as_ptr()) }, 0x5566_7788);
    }

    #[test]
    fn returns_then_advances_the_sequence_state() {
        let _guard = SEQUENCE_ID_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        for initial in [0, 1, 0x2468_ace0, 0xffff_fffe] {
            seed_sequence_id(initial);
            assert_eq!(unsafe { sequence_id_next() }, initial);
            assert_eq!(sequence_id(), initial.wrapping_add(1));
        }
    }

    #[test]
    fn wraps_after_returning_the_maximum_sequence_id() {
        let _guard = SEQUENCE_ID_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        seed_sequence_id(u32::MAX);
        assert_eq!(unsafe { sequence_id_next() }, u32::MAX);
        assert_eq!(sequence_id(), 0);
        assert_eq!(unsafe { sequence_id_next() }, 0);
        assert_eq!(sequence_id(), 1);
    }
}
