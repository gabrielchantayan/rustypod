//! Shared counter accumulator — `FUN_082c5718` @ 0x082c5718 (28 bytes; two
//! inbound plain `bl` call sites and no predicated `bl` call sites).
//!
//! Raw `osos.dec` establishes the exact extent `0x082c5718..0x082c5734`:
//! `ldr r3,[pc,#20]; ldr r2,[r3]; add r0,r2,r0; add r0,r0,r1; str r0,[r3];
//! mov r0,#1; bx lr`. The literal at `0x082c5734` is `0x08a0a748`; the next
//! separately linked function begins at `0x082c5738` with `mov r2,#0`.
//! The function wraps the fixed shared counter after adding both arguments,
//! then returns success (`1`) independently of the resulting counter value.
//!
//! Deliberate deviation: host builds use private backing for the fixed firmware
//! word so wrapping and return behavior can be tested without mapping retailOS
//! RAM.

use core::ptr;

/// Fixed shared word addressed by the original literal pool.
#[cfg(target_os = "none")]
const SHARED_COUNTER_ADDRESS: *mut u32 = 0x08a0_a748usize as *mut u32;

/// Host backing for the fixed firmware word.
#[cfg(not(target_os = "none"))]
static mut HOST_SHARED_COUNTER: u32 = 0;

#[inline(always)]
unsafe fn shared_counter_address() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        SHARED_COUNTER_ADDRESS
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(HOST_SHARED_COUNTER)
    }
}

/// accumulate_shared_counter — original: `FUN_082c5718` @ `0x082c5718` (28
/// bytes).
///
/// Adds `first` and `second` to the fixed shared counter with ARM wrapping
/// arithmetic, stores the result, and always returns one.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.accumulate_shared_counter")]
#[inline(never)]
pub unsafe extern "C" fn accumulate_shared_counter(first: u32, second: u32) -> u32 {
    let counter = unsafe { shared_counter_address() };
    let next = unsafe { ptr::read_volatile(counter) }
        .wrapping_add(first)
        .wrapping_add(second);
    unsafe { ptr::write_volatile(counter, next) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    static SHARED_COUNTER_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe fn set_shared_counter(value: u32) {
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(HOST_SHARED_COUNTER), value) };
    }

    #[test]
    fn accumulates_both_operands_and_always_returns_success() {
        let _guard = SHARED_COUNTER_TEST_LOCK.lock();

        for (initial, first, second, expected) in [
            (0, 0, 0, 0),
            (7, 3, 5, 15),
            (u32::MAX, 1, 0, 0),
            (u32::MAX - 2, 1, 4, 2),
        ] {
            unsafe { set_shared_counter(initial) };
            assert_eq!(unsafe { accumulate_shared_counter(first, second) }, 1);
            assert_eq!(unsafe { ptr::read_volatile(ptr::addr_of!(HOST_SHARED_COUNTER)) }, expected);
        }
    }
}
