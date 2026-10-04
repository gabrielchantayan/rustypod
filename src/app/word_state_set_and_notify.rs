//! `word_state_set_and_notify` — `FUN_081eb2a4` @ `0x081eb2a4`.
//! True extent: 32 bytes, ending at the next function at `0x081eb2c4`:
//! 24 instruction bytes and eight literal-pool bytes. Full-image A32 word
//! decoding finds two inbound plain BL calls (`0x0813f044`, `0x08227d8c`)
//! and zero predicated BL calls. This body contains no BL, only a tail BX.
//!
//! Stores the input word at receiver +0x40, then unconditionally dispatches
//! virtual slot +0x58 with (receiver, 0x2a2a2a2a, 0x8919). The virtual callee's
//! identity is unresolved; no fixed-address seam is inferred from its slot.
//! Deliberate deviations: host pointer fields widen structurally; target
//! offsets remain exact. Rust expresses the tail BX as a final call, retaining
//! its r0 result as an opaque u32 (both known callers ignore that result).

use core::ptr;

/// Recovered vtable prefix; the notification method occupies target +0x58.
#[repr(C)]
pub struct WordStateVtable {
    pub unresolved_slots: [usize; 22],
    pub notify: unsafe extern "C" fn(*mut WordStateReceiver, u32, u32) -> u32,
}

/// Recovered object prefix through the state word at target +0x40.
#[repr(C)]
pub struct WordStateReceiver {
    pub vtable: *const WordStateVtable,
    pub unresolved_words: [u32; 15],
    pub state: u32,
}

/// Replaces the state word and notifies even when its value is unchanged.
///
/// # Safety
/// `receiver` must be aligned and writable, with a readable vtable containing
/// a valid notification method accepting these unchecked retailOS arguments.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_state_set_and_notify(receiver: *mut WordStateReceiver, state: u32) -> u32 {
    ptr::write_volatile(ptr::addr_of_mut!((*receiver).state), state);
    let vtable = ptr::read_volatile(ptr::addr_of!((*receiver).vtable));
    let notify = ptr::read_volatile(ptr::addr_of!((*vtable).notify));
    notify(receiver, 0x2a2a_2a2a, 0x8919)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn observe_and_mutate(receiver: *mut WordStateReceiver, category: u32, resource: u32) -> u32 {
        assert_eq!(category, 0x2a2a_2a2a);
        assert_eq!(resource, 0x8919);
        let stored = (*receiver).state;
        (*receiver).unresolved_words[0] += 1;
        (*receiver).state = stored ^ 0xa5a5_a5a5;
        stored.rotate_left(7)
    }

    static VTABLE: WordStateVtable = WordStateVtable {
        unresolved_slots: [0; 22],
        notify: observe_and_mutate,
    };

    #[test]
    fn notification_observes_full_word_before_mutating_it() {
        let mut receiver = WordStateReceiver {
            vtable: &VTABLE, unresolved_words: [0x1357_2468; 15], state: 7,
        };
        receiver.unresolved_words[0] = 0;
        for value in [0, 1, 0x8000_0000, u32::MAX] {
            let result = unsafe { word_state_set_and_notify(&mut receiver, value) };
            assert_eq!(result, value.rotate_left(7));
            assert_eq!(receiver.state, value ^ 0xa5a5_a5a5);
            assert_eq!(&receiver.unresolved_words[1..], &[0x1357_2468; 14]);
        }
        assert_eq!(receiver.unresolved_words[0], 4);
    }

    #[test]
    fn unchanged_word_still_dispatches() {
        let mut receiver = WordStateReceiver {
            vtable: &VTABLE, unresolved_words: [0; 15], state: 0x1234_5678,
        };
        let result = unsafe { word_state_set_and_notify(&mut receiver, 0x1234_5678) };
        assert_eq!(receiver.unresolved_words[0], 1);
        assert_eq!(receiver.state, 0x1234_5678 ^ 0xa5a5_a5a5);
        assert_eq!(result, 0x1234_5678u32.rotate_left(7));
    }
}
