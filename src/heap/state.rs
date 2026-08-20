//! Opaque state-word lookup through a runtime global holder.
//!
//! `global_indirect_word_get` — original: `FUN_0807b280` @ 0x0807b280
//! (12-byte instruction body plus its 4-byte literal, 16-byte `functions.csv`
//! extent). Raw ARM is:
//!
//! ```text
//! 0807b280: ldr r0, [pc, #8]   ; 0x0807b290 = 0x089d03bc
//! 0807b284: ldr r0, [r0, #4]
//! 0807b288: ldr r0, [r0, #0x3c]
//! 0807b28c: bx  lr
//! ```
//!
//! Thus it follows the `+4` pointer in the opaque holder global at
//! 0x089d03bc and returns the raw word at that pointed-to object's `+0x3c`.
//! The only recovered direct caller, `FUN_080a0c60`, temporarily clears bit 0
//! of its own object's `+0x3c` word, performs a transfer, then restores this
//! value. That establishes neither the holder's type nor the word's meaning,
//! so this module deliberately uses an operation-only name.
//!
//! As with the other runtime-initialized 0x089dxxxx globals, the holder is
//! modeled by a crate static rather than mapped at the firmware address. Its
//! packed layout preserves the target's `holder + 4` pointer slot; host tests
//! install their own opaque state object through that same slot.

/// Byte offset of the pointer slot inside the holder global.
const HOLDER_STATE_OFFSET: usize = 4;

/// Byte offset of the returned raw word inside the opaque state object.
const STATE_WORD_OFFSET: usize = 0x3c;

/// Runtime-initialized holder at original address 0x089d03bc.
///
/// `packed(4)` keeps `state` at +4 on both the 32-bit target and 64-bit host.
/// The host pointer is consequently potentially unaligned and must only be
/// read or written through the unaligned helpers below.
#[repr(C, packed(4))]
pub struct GlobalIndirectHolder {
    _unknown: u32,
    state: *mut u8,
}

/// Model of the opaque runtime holder. It starts in the firmware's pre-init
/// state; an initializer or host test must publish the state object.
pub static mut GLOBAL_INDIRECT_HOLDER: GlobalIndirectHolder = GlobalIndirectHolder {
    _unknown: 0,
    state: core::ptr::null_mut(),
};

/// Loads the holder's +4 pointer exactly once. On target the aligned ARM word
/// load is volatile so a runtime publisher cannot be folded away; the packed
/// host representation requires an unaligned load.
#[inline(always)]
unsafe fn global_indirect_state() -> *mut u8 {
    let state_slot = core::ptr::addr_of!(GLOBAL_INDIRECT_HOLDER)
        .cast::<u8>()
        .add(HOLDER_STATE_OFFSET)
        .cast::<*mut u8>();
    #[cfg(target_os = "none")]
    {
        state_slot.read_volatile()
    }
    #[cfg(not(target_os = "none"))]
    {
        state_slot.read_unaligned()
    }
}

/// global_indirect_word_get — original: `FUN_0807b280` @ 0x0807b280
/// (12-byte body, plus the literal at 0x0807b290).
///
/// Performs precisely the original's two pointer dereferences: the opaque
/// holder's +4 state pointer, then that state's raw `u32` at +0x3c. Neither
/// pointer is checked, and the returned word is not interpreted as a pointer,
/// flag set, or owned value.
///
/// # Safety
/// The holder's +4 slot must contain a non-null pointer to at least 0x40
/// readable bytes, aligned for the raw `u32` load. This is the original ARM
/// load contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_indirect_word_get() -> u32 {
    let state = global_indirect_state();
    (state.add(STATE_WORD_OFFSET) as *const u32).read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::Mutex;

    use super::*;

    static HOLDER_LOCK: Mutex<()> = Mutex::new(());

    /// Rebinds only the exact `holder + 4` slot and returns its old value.
    unsafe fn replace_state(state: *mut u8) -> *mut u8 {
        let state_slot = core::ptr::addr_of_mut!(GLOBAL_INDIRECT_HOLDER)
            .cast::<u8>()
            .add(HOLDER_STATE_OFFSET)
            .cast::<*mut u8>();
        let old = state_slot.read_unaligned();
        state_slot.write_unaligned(state);
        old
    }

    #[test]
    fn loads_the_published_state_raw_word_at_3c() {
        let _lock = HOLDER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = [0u32; 16];
        state[14] = 0x1111_1111; // +0x38 must not be selected.
        state[15] = 0xdeaf_beef; // +0x3c is the raw result.

        unsafe {
            let old = replace_state(state.as_mut_ptr().cast());
            assert_eq!(global_indirect_word_get(), 0xdeaf_beef);
            replace_state(old);
        }
    }

    #[test]
    fn rereads_the_holder_pointer_for_each_call() {
        let _lock = HOLDER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut first = [0u32; 16];
        let mut second = [0u32; 16];
        first[15] = 0;
        second[15] = u32::MAX;

        unsafe {
            let old = replace_state(first.as_mut_ptr().cast());
            assert_eq!(global_indirect_word_get(), 0);
            replace_state(second.as_mut_ptr().cast());
            assert_eq!(global_indirect_word_get(), u32::MAX);
            replace_state(old);
        }
    }
}
