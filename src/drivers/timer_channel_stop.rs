//! S5L8702 timer-channel stop — `FUN_0836ddbc` @ `0x0836ddbc` (40 bytes,
//! 5 verified unconditional `bl` call sites: `0x080e995c`, `0x080e9964`,
//! `0x082bc550`, `0x0836dbe4`, and `0x0836dc4c`).
//!
//! Selects a 0x20-byte timer-channel block: channels 0 through 3 start at
//! `0x3c700000`, while all higher channel numbers use the firmware's separate
//! `0x3c700020 + channel * 0x20` calculation. It clears bit 0 in the command
//! word at block offset 4, preserving every other bit. Host builds back the
//! valid channel-register range with local storage; target builds access the
//! hardware register directly. The volatile accesses are deliberate: they
//! preserve the original MMIO read-modify-write under Rust's memory model.

/// First timer-channel MMIO block (`mov/addls r0, #0x3c700000`).
const TIMER_CHANNEL_BASE: usize = 0x3c70_0000;
/// Base selected by the `r0 > 3` path's literal pool word.
const TIMER_CHANNEL_EXTENDED_BASE: usize = 0x3c70_0020;
const TIMER_CHANNEL_STRIDE: usize = 0x20;
const TIMER_CHANNEL_COMMAND_OFFSET: usize = 4;

#[cfg(not(target_os = "none"))]
const HOST_TIMER_CHANNEL_WORDS: usize = 48;

/// Host backing for timer blocks 0 through 4. Tests use only these valid
/// hardware channel selectors; an out-of-range selector is as invalid on host
/// as its resulting unmapped MMIO address is on target.
#[cfg(not(target_os = "none"))]
static mut HOST_TIMER_CHANNEL_REGISTERS: [u32; HOST_TIMER_CHANNEL_WORDS] =
    [0; HOST_TIMER_CHANNEL_WORDS];

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn command_register(channel: u32) -> *mut u32 {
    let base = if channel <= 3 {
        TIMER_CHANNEL_BASE
    } else {
        TIMER_CHANNEL_EXTENDED_BASE
    };
    base.wrapping_add((channel as usize).wrapping_mul(TIMER_CHANNEL_STRIDE))
        .wrapping_add(TIMER_CHANNEL_COMMAND_OFFSET) as *mut u32
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn command_register(channel: u32) -> *mut u32 {
    let block = if channel <= 3 { channel } else { channel.wrapping_add(1) };
    unsafe {
        core::ptr::addr_of_mut!(HOST_TIMER_CHANNEL_REGISTERS)
            .cast::<u32>()
            .add(block as usize * (TIMER_CHANNEL_STRIDE / core::mem::size_of::<u32>()) + 1)
    }
}

/// Clears the running bit in an S5L8702 timer channel's command register.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timer_channel_stop(channel: u32) {
    let command = unsafe { command_register(channel) };
    let value = unsafe { command.read_volatile() };
    unsafe { command.write_volatile(value & !1) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TIMER_CHANNEL_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn reset_registers() {
        unsafe {
            core::ptr::addr_of_mut!(HOST_TIMER_CHANNEL_REGISTERS)
                .write([0; HOST_TIMER_CHANNEL_WORDS]);
        }
    }

    unsafe fn command(channel: u32) -> u32 {
        unsafe { command_register(channel).read_volatile() }
    }

    unsafe fn set_command(channel: u32, value: u32) {
        unsafe { command_register(channel).write_volatile(value) };
    }

    #[test]
    fn clears_only_running_bit_on_both_channel_address_paths() {
        let _lock = TIMER_CHANNEL_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            reset_registers();
            set_command(0, 0xffff_fffd);
            set_command(3, 0x8000_0003);
            set_command(4, 0x7fff_ffff);

            timer_channel_stop(0);
            timer_channel_stop(3);
            timer_channel_stop(4);

            assert_eq!(command(0), 0xffff_fffc, "channel 0 uses the direct base");
            assert_eq!(command(3), 0x8000_0002, "channel 3 is the last direct-base channel");
            assert_eq!(command(4), 0x7fff_fffe, "channel 4 takes the literal-base path");
        }
    }

    #[test]
    fn stopping_a_stopped_channel_is_idempotent() {
        let _lock = TIMER_CHANNEL_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            reset_registers();
            set_command(1, 0);
            timer_channel_stop(1);
            timer_channel_stop(1);
            assert_eq!(command(1), 0, "a clear running bit remains clear");
        }
    }
}
