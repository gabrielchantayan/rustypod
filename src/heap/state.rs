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
/// Byte offset of the returned raw word at the start of the opaque state object.
const STATE_ZERO_WORD_OFFSET: usize = 0;

/// Byte offset of the status word inside the opaque state object.
const STATE_STATUS_OFFSET: usize = 0x18;


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

/// global_indirect_state_word_get — original: `FUN_080ee2a0` @ 0x080ee2a0
/// (16-byte instruction body; the literal at 0x080ee2b0 is data, and the
/// independently linked next function begins at 0x080ee2b4).
///
/// Raw ARM is `ldr r0,[pc,#8]; ldr r0,[r0,#4]; ldr r0,[r0,#0]; bx lr`.
/// Whole-image decoding of ARM B/BL-immediate words finds three inbound
/// calls, all unconditional `bl` (none predicated): 0x08074d74, 0x08074ef8,
/// and 0x0836a100.
///
/// Performs precisely the original's two unchecked pointer dereferences:
/// the global holder's +4 state pointer, then that state's raw `u32` at +0.
/// The port deliberately preserves the raw word without a null guard, cache,
/// ownership model, or bit interpretation.
///
/// # Safety
/// The holder's +4 slot must contain a non-null pointer to at least four
/// readable bytes, aligned for the raw `u32` load. This is the original ARM
/// load contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_indirect_state_word_get() -> u32 {
    let state = global_indirect_state();
    (state.add(STATE_ZERO_WORD_OFFSET) as *const u32).read()
}


/// global_indirect_status_get — original: `FUN_080ee2b4` @ 0x080ee2b4
/// (16-byte instruction body, followed by the separately located literal at
/// 0x080ee2c4; the next function starts at 0x080ee2c8).
///
/// Raw ARM is `ldr r0,[pc,#8]; ldr r0,[r0,#4]; ldr r0,[r0,#0x18]; bx lr`.
/// A complete decode of every ARM B/BL-immediate word in `osos.dec` finds ten
/// direct callers, all unconditional `bl`; no caller passes an argument.
///
/// Performs precisely the original's two unchecked pointer dereferences: the
/// global holder's +4 state pointer, then that state's raw `u32` at +0x18.
/// The recovered callers only test result bits, so this port deliberately
/// preserves the word without assigning bit meanings, caching it, or adding a
/// null guard.
///
/// # Safety
/// The holder's +4 slot must contain a non-null pointer to at least 0x1c
/// readable bytes, aligned for the raw `u32` load. This is the original ARM
/// load contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_indirect_status_get() -> u32 {
    let state = global_indirect_state();
    (state.add(STATE_STATUS_OFFSET) as *const u32).read()
}

/// global_indirect_command_response_get — original: `FUN_080f3c58` @ 0x080f3c58.
/// True extent: 20 bytes (16 instruction bytes plus the literal at 0x080f3c68),
/// ending at the independently linked next function, 0x080f3c6c.
///
/// Raw words e59f0008 e5900004 e5900020 e12fff1e load holder +4, then
/// state +0x20, and return. Whole-image ARM BL decoding finds two plain
/// callers (0x080775d0 and 0x080ee344), zero predicated callers, and no
/// outgoing calls. The transaction worker copies this raw command response
/// to its output; card initialization polls its high bit after SEND_OP_COND.
///
/// Deliberate deviation: reuse the existing packed crate-static holder model
/// rather than the fixed firmware global at 0x089d03bc. Preserve every bit
/// without null checks, caching, or interpreting command-specific fields.
///
/// # Safety
/// The holder's +4 pointer must reference at least 0x24 readable bytes,
/// aligned for a `u32` load, and remain valid throughout the call.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_indirect_command_response_get() -> u32 {
    let state = global_indirect_state();
    (state.cast::<u32>().add(8)).read()
}

/// global_indirect_transfer_state_get — original: `FUN_080f3c6c` @ 0x080f3c6c.
/// True extent: 20 bytes (16 instruction bytes and the literal at 0x080f3c7c),
/// ending at the distinct next function, 0x080f3c80.
///
/// Raw ARM is `ldr r0,[pc,#8]; ldr r0,[r0,#4]; ldr r0,[r0,#0x10]; bx lr`.
/// Whole-image decoding finds two plain BL callers (0x080774c8 and
/// 0x080a0d7c), zero predicated BL callers, and no outgoing calls.
///
/// Follows the global holder's +4 pointer and returns the raw transfer-state
/// word at +0x10. Callers poll masks 0x30 and 0x0f; their bit meanings remain
/// unspecified. Deliberate deviation: reuse the existing crate-static holder
/// model rather than the firmware address. No null guard or caching is added.
///
/// # Safety
/// The holder's +4 slot must point to at least 0x14 readable bytes, aligned
/// for a `u32` load. The published object must remain valid during the call.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_indirect_transfer_state_get() -> u32 {
    let state = global_indirect_state();
    (state.cast::<u32>().add(4)).read()
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
    fn command_response_preserves_bits_and_rereads_state_and_holder() {
        let _lock = HOLDER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut first = [0x1111_1111u32; 10];
        let mut second = [0x2222_2222u32; 10];
        first[8] = 0;
        second[8] = 0x8000_0000;

        unsafe {
            let old = replace_state(first.as_mut_ptr().cast());
            assert_eq!(global_indirect_command_response_get(), 0);
            for value in [1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                first[8] = value;
                assert_eq!(global_indirect_command_response_get(), value);
            }
            replace_state(second.as_mut_ptr().cast());
            assert_eq!(global_indirect_command_response_get(), 0x8000_0000);
            replace_state(old);
        }
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
    #[test]
    fn loads_the_published_status_raw_word_at_18() {
        let _lock = HOLDER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = [0u32; 8];
        state[5] = 0x1111_1111; // +0x14 must not be selected.
        state[6] = u32::MAX; // +0x18 is the raw result.
        state[7] = 0x2222_2222; // +0x1c must not be selected.

        unsafe {
            let old = replace_state(state.as_mut_ptr().cast());
            assert_eq!(global_indirect_status_get(), u32::MAX);
            replace_state(old);
        }
    }

    #[test]
    fn status_get_rereads_the_holder_pointer_for_each_call() {
        let _lock = HOLDER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut first = [0u32; 8];
        let mut second = [0u32; 8];
        first[6] = 0;
        second[6] = 0x8000_0015;

        unsafe {
            let old = replace_state(first.as_mut_ptr().cast());
            assert_eq!(global_indirect_status_get(), 0);
            replace_state(second.as_mut_ptr().cast());
            assert_eq!(global_indirect_status_get(), 0x8000_0015);
            replace_state(old);
        }
    }

    #[test]
    fn loads_the_published_state_raw_word_at_zero() {
        let _lock = HOLDER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = [0u32; 2];
        state[0] = 0xa5a5_5a5a; // +0 is the raw result.
        state[1] = 0x1111_1111; // +4 must not be selected.

        unsafe {
            let old = replace_state(state.as_mut_ptr().cast());
            assert_eq!(global_indirect_state_word_get(), 0xa5a5_5a5a);
            replace_state(old);
        }
    }

    #[test]
    fn state_word_get_rereads_the_holder_pointer_for_each_call() {
        let _lock = HOLDER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut first = [0u32; 1];
        let mut second = [u32::MAX; 1];

        unsafe {
            let old = replace_state(first.as_mut_ptr().cast());
            assert_eq!(global_indirect_state_word_get(), 0);
            replace_state(second.as_mut_ptr().cast());
            assert_eq!(global_indirect_state_word_get(), u32::MAX);
            replace_state(old);
        }
    }

    #[test]
    fn transfer_state_get_preserves_bits_and_rereads_state() {
        let _lock = HOLDER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut first = [0x1111_1111u32; 6];
        let mut second = [0x2222_2222u32; 6];
        unsafe {
            let old = replace_state(first.as_mut_ptr().cast());
            for word in [0, 0x0f, 0x30, 0x8000_0000, u32::MAX] {
                first[4] = word;
                assert_eq!(global_indirect_transfer_state_get(), word);
            }
            second[4] = 0xa5a5_5a5a;
            replace_state(second.as_mut_ptr().cast());
            assert_eq!(global_indirect_transfer_state_get(), second[4]);
            replace_state(old);
        }
    }
}
