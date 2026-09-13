//! Stops an optional timer, then clears an embedded [`BitSet`].
//!
//! `timer_stop_then_clear_bit_set` — original: `FUN_081ccb78` at load address
//! **0x081ccb78** (**36 bytes**, 0x081ccb78..0x081ccb9c; the separately linked
//! sibling begins with `push {r4, r5, r6, r7, r8, lr}` at 0x081ccb9c, with no
//! literal pool). A decode of every ARM B/BL word in `osos.dec` finds **six
//! direct call sites**, all unconditional `bl` instructions at 0x081cc8ac,
//! 0x081cc8dc, 0x081cc9e4, 0x081ccd08, 0x081ccdf8, and 0x081ccf64; there are
//! no predicated calls.
//!
//! The raw instructions load the optional timer from `this + 0x8e4` and call
//! [`timer_stop`] only when it is non-null. They then compute the embedded bit
//! set at `this + 0x8e8` and tail-branch to [`bit_set_clear_all`]. Thus every
//! call clears the bit set's word storage and cardinality, while a present
//! timer is stopped first. Ghidra instead joins an unrelated memzero call into
//! this body; the raw `b 0x082747b8` at 0x081ccb98 establishes the bit-set
//! tail call.
//!
//! Deliberate deviation: Rust makes the final tail branch an ordinary direct
//! call to the already ported helper. The void ABI leaves no observable result
//! after that helper returns.

use crate::cxx::bit_set::{bit_set_clear_all, BitSet};
use crate::drivers::timer::timer_stop;

const TIMER_OFFSET: usize = 0x8e4;
const BIT_SET_OFFSET: usize = 0x8e8;

/// Stops the optional timer at `this + 0x8e4`, then clears the [`BitSet`] at
/// `this + 0x8e8`.
///
/// # Safety
///
/// `this` must point to a live object at least `BIT_SET_OFFSET +
/// size_of::<BitSet>()` bytes long. Its bit set must satisfy
/// [`bit_set_clear_all`]'s storage contract. If the timer field is nonzero,
/// it must point to a live timer object accepted by [`timer_stop`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timer_stop_then_clear_bit_set(this: *mut u8) {
    let timer = unsafe { this.add(TIMER_OFFSET).cast::<u32>().read() as usize as *mut u8 };
    if !timer.is_null() {
        unsafe { timer_stop(timer) };
    }
    unsafe { bit_set_clear_all(this.add(BIT_SET_OFFSET).cast::<BitSet>()) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::timer::{TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use std::sync::{LazyLock, Mutex};

    const OWNER_BYTES: usize = BIT_SET_OFFSET + core::mem::size_of::<BitSet>();
    const SLAB_BYTES: usize = 0x100;
    const TIMER_SLAB_OFFSET: usize = 0x40;
    const TIMER_STATE_OFFSET: usize = 0x20;

    static SLAB: LazyLock<usize> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::TIMER_STOP_THEN_CLEAR_BIT_SET,
            SLAB_BYTES,
        )
        .map(|slab| slab as usize)
        .unwrap_or(0)
    });
    static LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn slab() -> Option<*mut u8> {
        let slab = *SLAB;
        if slab == 0 { None } else { Some(slab as *mut u8) }
    }

    unsafe fn embedded_bit_set(owner: *mut u8) -> *mut BitSet {
        unsafe { owner.add(BIT_SET_OFFSET).cast::<BitSet>() }
    }

    #[test]
    fn no_timer_still_clears_all_rounded_words_and_cardinality() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = slab() else { return };
        let mut owner = [0u32; OWNER_BYTES / core::mem::size_of::<u32>()];

        unsafe {
            core::ptr::write_bytes(slab, 0xa5, SLAB_BYTES);
            let set = embedded_bit_set(owner.as_mut_ptr().cast());
            (*set).bit_capacity = 33;
            (*set).cardinality = 2;
            (*set).words = slab as usize as u32;
            (*set).heap_tag = 0;

            timer_stop_then_clear_bit_set(owner.as_mut_ptr().cast());

            assert_eq!((*set).cardinality, 0);
            assert_eq!(core::slice::from_raw_parts(slab, 8), [0; 8]);
            assert_eq!(core::slice::from_raw_parts(slab.add(8), 8), [0xa5; 8]);
        }
    }

    #[test]
    fn present_timer_is_stopped_before_the_embedded_set_is_cleared() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = slab() else { return };
        let mut owner = [0u32; OWNER_BYTES / core::mem::size_of::<u32>()];

        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_BYTES);
            let timer = slab.add(TIMER_SLAB_OFFSET);
            timer.add(TIMER_STATE_OFFSET).cast::<u32>().write(TIMER_STATE_RUNNING);
            owner[TIMER_OFFSET / core::mem::size_of::<u32>()] = timer as usize as u32;

            let set = embedded_bit_set(owner.as_mut_ptr().cast());
            (*set).bit_capacity = 1;
            (*set).cardinality = 1;
            (*set).words = slab as usize as u32;
            slab.cast::<u32>().write(1);

            timer_stop_then_clear_bit_set(owner.as_mut_ptr().cast());

            assert_eq!(timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(), TIMER_STATE_STOPPED);
            assert_eq!((*set).cardinality, 0);
            assert_eq!(slab.cast::<u32>().read(), 0);
        }
    }
}
