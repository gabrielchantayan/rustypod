//! S5L8702 timer-channel divider configuration — `FUN_0836dc14` @
//! `0x0836dc14` (136 bytes; 1 plain and 1 predicated inbound `bl` site).
//!
//! Raw ARM establishes the true `0x0836dc14..0x0836dc9c` extent: 128 bytes
//! of instructions followed by the two literal words used for the extended
//! channel base and source clock. The body contains two plain `bl` calls and
//! no predicated calls: it clears the channel running bit and divides by the
//! existing ADS unsigned divider.
//!
//! Repeatedly divides the 3 MHz source clock by `requested_hz * divider`,
//! increasing `divider` from one until the quotient fits in 16 bits. If no
//! quotient fits by divider 1024, the original's condition flags keep it
//! looping. It then writes the quotient, divider-minus-one, mode `0x40`, and
//! sets command bit 1 in the selected 0x20-byte timer-channel block.
//!
//! Deliberate deviation: host builds use local register storage because the
//! target's `0x3c700000` MMIO region is unavailable. The target uses volatile
//! reads and writes, preserving the hardware read-modify-write operations.

#[cfg(target_os = "none")]
use crate::drivers::timer_channel_stop::timer_channel_stop;

use crate::runtime::rt_div::__rt_udiv;

const TIMER_CHANNEL_BASE: usize = 0x3c70_0000;
const TIMER_CHANNEL_EXTENDED_BASE: usize = 0x3c70_0020;
const TIMER_CHANNEL_STRIDE: usize = 0x20;
const TIMER_CLOCK_HZ: u32 = 3_000_000;
const COMMAND_WORD: usize = 1;
const DIVIDER_WORD: usize = 2;
const PRESCALER_WORD: usize = 4;
const MODE_WORD: usize = 0;

#[cfg(not(target_os = "none"))]
const HOST_TIMER_CHANNEL_WORDS: usize = 48;

#[cfg(not(target_os = "none"))]
static mut HOST_TIMER_CHANNEL_REGISTERS: [u32; HOST_TIMER_CHANNEL_WORDS] = [0; HOST_TIMER_CHANNEL_WORDS];

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn channel_registers(channel: u32) -> *mut u32 {
    let base = if channel <= 3 { TIMER_CHANNEL_BASE } else { TIMER_CHANNEL_EXTENDED_BASE };
    base.wrapping_add((channel as usize).wrapping_mul(TIMER_CHANNEL_STRIDE)) as *mut u32
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn channel_registers(channel: u32) -> *mut u32 {
    let block = if channel <= 3 { channel } else { channel.wrapping_add(1) };
    unsafe { core::ptr::addr_of_mut!(HOST_TIMER_CHANNEL_REGISTERS).cast::<u32>().add(block as usize * 8) }
}

/// Configures one timer channel's 16-bit divider and starts its mode.
///
/// `timer_channel_configure` — original `FUN_0836dc14` @ `0x0836dc14`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timer_channel_configure(channel: u32, requested_hz: u32) {
    let registers = unsafe { channel_registers(channel) };
    #[cfg(target_os = "none")]
    unsafe { timer_channel_stop(channel) };

    let command = unsafe { registers.add(COMMAND_WORD) };

    #[cfg(not(target_os = "none"))]
    unsafe { command.write_volatile(command.read_volatile() & !1) };
    let mut divider = 0u32;
    let mut quotient = 0u32;
    loop {
        divider = divider.wrapping_add(1);
        quotient = unsafe { __rt_udiv(TIMER_CLOCK_HZ, requested_hz.wrapping_mul(divider)) };
        if quotient <= u16::MAX as u32 {
            break;
        }
    }

    unsafe {
        registers.add(DIVIDER_WORD).write_volatile(quotient);
        registers.add(PRESCALER_WORD).write_volatile(divider.wrapping_sub(1));
        registers.add(MODE_WORD).write_volatile(0x40);
        command.write_volatile(command.read_volatile() | 2);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TIMER_CHANNEL_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn reset_registers() {
        unsafe { core::ptr::addr_of_mut!(HOST_TIMER_CHANNEL_REGISTERS).write([0; HOST_TIMER_CHANNEL_WORDS]) };
    }

    unsafe fn registers(channel: u32) -> *mut u32 {
        unsafe { channel_registers(channel) }
    }

    #[test]
    fn configures_direct_and_extended_channels_without_losing_command_bits() {
        let _lock = TIMER_CHANNEL_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            reset_registers();
            registers(3).add(COMMAND_WORD).write_volatile(0xffff_ffff);
            registers(4).add(COMMAND_WORD).write_volatile(0x8000_0001);

            timer_channel_configure(3, 1_000);
            timer_channel_configure(4, 50);

            assert_eq!(registers(3).read_volatile(), 0x40);
            assert_eq!(registers(3).add(COMMAND_WORD).read_volatile(), 0xffff_fffe);
            assert_eq!(registers(3).add(DIVIDER_WORD).read_volatile(), 3_000);
            assert_eq!(registers(3).add(PRESCALER_WORD).read_volatile(), 0);
            assert_eq!(registers(4).add(COMMAND_WORD).read_volatile(), 0x8000_0002);
            assert_eq!(registers(4).add(DIVIDER_WORD).read_volatile(), 60_000);
            assert_eq!(registers(4).add(PRESCALER_WORD).read_volatile(), 0);
        }
    }

    #[test]
    fn increases_divider_until_the_quotient_fits_and_preserves_wrapping_product() {
        let _lock = TIMER_CHANNEL_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            reset_registers();
            timer_channel_configure(0, 1);
            assert_eq!(registers(0).add(DIVIDER_WORD).read_volatile(), 65_217);
            assert_eq!(registers(0).add(PRESCALER_WORD).read_volatile(), 45);
            timer_channel_configure(1, u32::MAX);
            assert_eq!(registers(1).add(DIVIDER_WORD).read_volatile(), 0);
            assert_eq!(registers(1).add(PRESCALER_WORD).read_volatile(), 0);
        }
    }
}
