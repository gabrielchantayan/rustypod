//! Shared counter increment — `FUN_08149da0` @ 0x08149da0 (20 bytes; four
//! inbound plain `bl` call sites and no predicated `bl` call sites).
//!
//! Raw `osos.dec` establishes the exact extent `0x08149da0..0x08149db4`:
//! `ldr r1,[pc,#12]; ldr r0,[r1]; add r0,r0,#1; str r0,[r1]; bx lr`. The
//! separately linked next function begins at `0x08149db4` with `mov r0,#0x21`.
//! The literal is the shared word at `0x089cb1e8`. The helper increments that
//! word with ARM's wrapping arithmetic and returns the new value. Its callers
//! retain the returned value as a shared token; the owning subsystem is not
//! recovered, so this port names only the verified counter behavior.
//!
//! Deliberate deviation: host builds use private backing for the fixed firmware
//! word so the edge cases can be tested without mapping retailOS RAM.

use core::ptr;

/// Fixed firmware word addressed by the original literal pool.
#[cfg(target_os = "none")]
const SHARED_COUNTER_ADDRESS: *mut u32 = 0x089c_b1e8usize as *mut u32;

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

/// increment_shared_counter — original: `FUN_08149da0` @ `0x08149da0` (20
/// bytes).
///
/// Increments and returns the fixed shared counter, wrapping from `u32::MAX`
/// to zero. The retail instruction sequence performs volatile-like fixed RAM
/// accesses; this port preserves those accesses with volatile loads and stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.increment_shared_counter")]
#[inline(never)]
pub unsafe extern "C" fn increment_shared_counter() -> u32 {
    let counter = unsafe { shared_counter_address() };
    let next = unsafe { ptr::read_volatile(counter) }.wrapping_add(1);
    unsafe { ptr::write_volatile(counter, next) };
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    static SHARED_COUNTER_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe fn set_shared_counter(value: u32) {
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(HOST_SHARED_COUNTER), value) };
    }

    #[test]
    fn increments_and_returns_the_shared_counter() {
        let _guard = SHARED_COUNTER_TEST_LOCK.lock();

        for (initial, expected) in [(0, 1), (41, 42), (u32::MAX - 1, u32::MAX), (u32::MAX, 0)] {
            unsafe { set_shared_counter(initial) };
            assert_eq!(unsafe { increment_shared_counter() }, expected);
            assert_eq!(unsafe { ptr::read_volatile(ptr::addr_of!(HOST_SHARED_COUNTER)) }, expected);
        }
    }
}
