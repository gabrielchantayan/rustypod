//! `notify_wait_enter` — original: `FUN_0836d854` @ **0x0836d854** (36 bytes,
//! `0x0836d854..0x0836d878`; **2 inbound plain `bl` call sites**, no predicated
//! `bl` call sites, binary-scanned).
//!
//! Configures GPIO 6 for function 3, then tail-calls the same GPIO command
//! writer to configure GPIO 7 for function 5. The tail call returns the
//! writer's unconditional zero result. Deliberate deviation: Rust uses a
//! normal return after the second call; this preserves the visible call order,
//! register arguments, GPIO writes, and returned value without reproducing the
//! ARM tail branch.

use super::gpio_cmd::gpio_pin_configure;

const FIRST_PIN: u32 = 6;
const FIRST_FUNCTION: u32 = 3;
const SECOND_PIN: u32 = 7;
const SECOND_FUNCTION: u32 = 5;

/// `notify_wait_enter` — original @ 0x0836d854. Emits the two GPIO commands
/// that precede a timer-armed event wait.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn notify_wait_enter() -> u32 {
    gpio_pin_configure(FIRST_PIN, FIRST_FUNCTION, 0);
    gpio_pin_configure(SECOND_PIN, SECOND_FUNCTION, 0)
}

#[cfg(test)]
mod tests {
    use super::notify_wait_enter;
    use crate::drivers::gpio_cmd::host_gpiocmd;
    use core::ptr::addr_of;

    #[test]
    fn emits_both_gpio_commands_in_order_and_returns_zero() {
        unsafe {
            let before = core::ptr::read_volatile(addr_of!(host_gpiocmd::WRITE_COUNT));
            assert_eq!(notify_wait_enter(), 0);
            assert_eq!(
                core::ptr::read_volatile(addr_of!(host_gpiocmd::WRITE_COUNT)),
                before + 2
            );
            assert_eq!(
                core::ptr::read_volatile(addr_of!(host_gpiocmd::LAST_COMMAND)),
                0x00_07_05
            );
        }
    }
}
