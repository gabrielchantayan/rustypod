//! `transfer_slot_try_process` — original: `FUN_081e476c` @ `0x081e476c`
//! (68 bytes; true extent `0x081e476c..0x081e47af`).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM words establish one outbound plain unconditional `bl` to
//! [`transfer_slot_process`] and no predicated outbound `bl` forms. Three
//! inbound direct plain `bl` sites occur in `FUN_081e5828`; no predicated
//! inbound call forms occur. For the selected 0x50-byte slot, a nonzero byte
//! at +0x1284 bypasses processing. Otherwise it forwards the word at +0x125c
//! and an output count; on failure this function restores +0x125c from
//! +0x1244 and returns 0, while a successful process returns 3.
//!
//! # Deliberate deviations
//!
//! The raw caller passes an uninitialized stack word, but
//! [`transfer_slot_process`] immediately zeros it; Rust initializes it to zero
//! without changing the observed value at the call boundary.

use super::transfer_slot_process::transfer_slot_process;

/// Attempts to process a selected transfer slot and restores its saved source
/// word when the attempt fails or the slot is disabled.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn transfer_slot_try_process(context: *mut u8, slot_index: u32) -> u32 {
    const SLOT_SIZE: usize = 0x50;
    const SOURCE: usize = 0x125c;
    const SAVED_SOURCE: usize = 0x1244;
    const DISABLED: usize = 0x1284;

    let slot = unsafe { context.add(slot_index as usize * SLOT_SIZE) };
    if unsafe { slot.add(DISABLED).read() } == 0 {
        let source = unsafe { (slot.add(SOURCE) as *const u32).read() };
        let mut transferred = 0;
        let result = unsafe { transfer_slot_process(context, slot_index, source, &mut transferred) };
        if result != 0 {
            return 3;
        }
    }

    unsafe { (slot.add(SOURCE) as *mut u32).write((slot.add(SAVED_SOURCE) as *const u32).read()) };
    0
}

