//! Mailbox-controller reset.
//!
//! `mailbox_controller_reset` — original: `FUN_0807f5a0` @ `0x0807f5a0`
//! (36 bytes, `0x0807f5a0..0x0807f5c4`; the literal at `0x0807f5c0` is part
//! of the body and the next real function starts at `0x0807f5c4`). Raw ARM
//! words establish two plain inbound `bl` call sites and one predicated `bl`
//! call site. The body has no `bl` instructions.
//!
//! Sets the three controller words at `0x39600000`, then tail-branches to the
//! separate 48-byte body at `0x080b48a8`, which clears five mailbox words
//! rooted at `0x39610000`. The repeated stores at the base and final mailbox
//! word are retained.
//!
//! Deliberate deviation: the original tail branch is inlined because its
//! target has no verified semantic identity in `names.yaml`, so a callee seam
//! would invent one. Volatile stores preserve the observable fixed-address
//! write sequence although retailOS uses ordinary `str` instructions.

use core::ptr;

const CONTROLLER_BASE: *mut u32 = 0x3960_0000 as *mut u32;
const MAILBOX_BASE: *mut u32 = 0x3961_0000 as *mut u32;

const CONTROLLER_STATUS_WORD: usize = 3;
const CONTROLLER_RESULT_WORD: usize = 7;
const CONTROLLER_MODE_WORD: usize = 11;
const MAILBOX_SECOND_WORD: usize = 0x1_0000;
const MAILBOX_THIRD_WORD: usize = 0x80_40;
const MAILBOX_FINAL_WORD: usize = 0x14000;

#[inline(always)]
unsafe fn reset_regions(controller: *mut u32, mailbox: *mut u32) {
    unsafe {
        ptr::write_volatile(controller.add(CONTROLLER_MODE_WORD), 2);
        ptr::write_volatile(controller.add(CONTROLLER_RESULT_WORD), u32::MAX);
        ptr::write_volatile(controller.add(CONTROLLER_STATUS_WORD), 0);

        ptr::write_volatile(mailbox, u32::MAX);
        ptr::write_volatile(mailbox, u32::MAX);
        ptr::write_volatile(mailbox.add(MAILBOX_SECOND_WORD), u32::MAX);
        ptr::write_volatile(mailbox.add(MAILBOX_THIRD_WORD), u32::MAX);
        ptr::write_volatile(mailbox.add(MAILBOX_FINAL_WORD), u32::MAX);
        ptr::write_volatile(mailbox.add(MAILBOX_FINAL_WORD), u32::MAX);
    }
}

/// Resets the fixed controller state and its associated mailbox words.
///
/// # Safety
///
/// The fixed hardware addresses must be mapped and permit 32-bit volatile
/// writes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mailbox_controller_reset() {
    unsafe { reset_regions(CONTROLLER_BASE, MAILBOX_BASE) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn resets_controller_fields_and_every_mailbox_word() {
        let mut controller = [0x1357_9bdf; 12];
        let mut mailbox = std::vec![0x2468_ace0; MAILBOX_FINAL_WORD + 1];

        unsafe { reset_regions(controller.as_mut_ptr(), mailbox.as_mut_ptr()) };

        assert_eq!(controller[CONTROLLER_MODE_WORD], 2);
        assert_eq!(controller[CONTROLLER_RESULT_WORD], u32::MAX);
        assert_eq!(controller[CONTROLLER_STATUS_WORD], 0);
        assert_eq!(controller[0], 0x1357_9bdf);
        assert_eq!(mailbox[0], u32::MAX);
        assert_eq!(mailbox[MAILBOX_SECOND_WORD], u32::MAX);
        assert_eq!(mailbox[MAILBOX_THIRD_WORD], u32::MAX);
        assert_eq!(mailbox[MAILBOX_FINAL_WORD], u32::MAX);
        assert_eq!(mailbox[1], 0x2468_ace0);
    }
}
