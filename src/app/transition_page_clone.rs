//! `transition_page_clone` — original: `FUN_08152c04` @ 0x08152c04 (184
//! bytes, 0x08152c04..0x08152cbc; **4 unconditional `bl` call sites and 0
//! predicated forms**, decoded from raw `osos.dec` words). The next real
//! function starts at 0x08152cbc with `push {r3,r4,r5,r6,r7,lr}`.
//!
//! Clones a transition page from `source` into caller-provided `destination`:
//! it invokes the stock page initializer with the page displacement, re-arms
//! the destination's timed transition to the source transition value over one
//! second, assigns the two three-component fixed-value records, then copies
//! and displacement-adjusts the remaining page state words.
//!
//! Deliberate deviations: the initializer at 0x081525bc has no recovered
//! semantic identity or Rust port, so target builds call that exact stock ABI
//! address. Host builds make that opaque stock call a no-op; tests cover this
//! function's independently decoded post-initialization stores.

use crate::app::fixed3_assign::fixed3_assign;
use crate::app::timed_transition::{timed_transition_init, TimedTransition};

#[cfg(target_os = "none")]
const STOCK_PAGE_INITIALIZER: usize = 0x0815_25bc;
const PAGE_DISPLACEMENT: u32 = 0x000f_0000;
const TRANSITION_OFFSET: usize = 0x128;
const PAGE_OFFSET: usize = 0x12c;
const PAGE_POSITION_OFFSET: usize = 0x130;
const PAGE_STATE_OFFSET: usize = 0x140;

#[cfg(target_os = "none")]
unsafe fn call_stock_page_initializer(
    destination: *mut u32,
    source_transition_value: u32,
    page_position: u32,
    page: u32,
    page_displacement: u32,
    unused: u32,
) {
    let initializer: unsafe extern "C" fn(*mut u32, u32, u32, u32, u32, u32) =
        unsafe { core::mem::transmute(STOCK_PAGE_INITIALIZER) };
    unsafe {
        initializer(destination, source_transition_value, page_position, page, page_displacement, unused);
    }
}

#[cfg(not(target_os = "none"))]
unsafe fn call_stock_page_initializer(
    _destination: *mut u32,
    _source_transition_value: u32,
    _page_position: u32,
    _page: u32,
    _page_displacement: u32,
    _unused: u32,
) {
}

#[cfg(target_os = "none")]
unsafe fn rearm_timed_transition(destination_transition: *mut TimedTransition, target_value: u32) {
    unsafe {
        timed_transition_init(destination_transition, target_value, 1000, 0, 0, 0);
    }
}

#[cfg(not(target_os = "none"))]
unsafe fn rearm_timed_transition(destination_transition: *mut TimedTransition, target_value: u32) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*destination_transition).wheel_rank), 1);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*destination_transition).start_value), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*destination_transition).target_value), target_value);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*destination_transition).duration_ms), 1000);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*destination_transition).aux_value), 0);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*destination_transition).owner_or_self),
            destination_transition as usize as u32,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*destination_transition).armed), 0);
    }
}
#[cfg(target_os = "none")]
unsafe fn assign_fixed3(destination: *mut u32, source: *const u32) {
    unsafe { fixed3_assign(destination.cast(), source.cast()); }
}

#[cfg(not(target_os = "none"))]
unsafe fn assign_fixed3(destination: *mut u32, source: *const u32) {
    unsafe {
        for member in 0..3 {
            for word in 1..6 {
                core::ptr::write_volatile(
                    destination.add(member * 6 + word),
                    core::ptr::read_volatile(source.add(member * 6 + word)),
                );
            }
        }
    }
}


/// transition_page_clone — original: `FUN_08152c04` @ 0x08152c04 (184 bytes;
/// 4 unconditional `bl` call sites, binary-decoded).
///
/// `destination` and `source` are aligned writable/readable retailOS page
/// objects. `page_displacement` is signed in the original and therefore wraps
/// in the same two's-complement manner when scaled by Q16.16 page width.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn transition_page_clone(
    destination: *mut u32,
    source: *const u32,
    page_displacement: i32,
    unused: u32,
) {
    unsafe {
        let source_transition = core::ptr::read_volatile(source.add(TRANSITION_OFFSET / 4));
        call_stock_page_initializer(
            destination,
            core::ptr::read_volatile((source_transition as *const u32).add(7)),
            core::ptr::read_volatile(source.add(PAGE_POSITION_OFFSET / 4))
                .wrapping_add(page_displacement as u32),
            core::ptr::read_volatile(source.add(PAGE_OFFSET / 4))
                .wrapping_add(page_displacement as u32),
            page_displacement as u32,
            unused,
        );
        rearm_timed_transition(
            core::ptr::read_volatile(destination.add(TRANSITION_OFFSET / 4)) as *mut TimedTransition,
            core::ptr::read_volatile((source_transition as *const u32).add(7)),
        );
        assign_fixed3(destination.add(8 / 4), source.add(8 / 4));
        assign_fixed3(destination.add(0x50 / 4), source.add(0x50 / 4));
        let displacement = (page_displacement as u32).wrapping_mul(PAGE_DISPLACEMENT);
        core::ptr::write_volatile(
            destination.add(0x0c / 4),
            core::ptr::read_volatile(source.add(0x0c / 4)).wrapping_add(displacement),
        );
        core::ptr::write_volatile(destination.add(0x10 / 4), 0);
        core::ptr::write_volatile(
            destination.add(PAGE_STATE_OFFSET / 4),
            core::ptr::read_volatile(source.add(PAGE_STATE_OFFSET / 4)).wrapping_add(displacement),
        );
        for offset in [0x164, 0x188, 0x1ac, 0x1d0, 0x1f4] {
            core::ptr::write_volatile(
                destination.add(offset / 4),
                core::ptr::read_volatile(source.add(offset / 4)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x4000;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TRANSITION_PAGE_CLONE, SLAB_LEN).map(|pointer| pointer as usize)
    });

    #[test]
    fn clones_fixed_records_and_adjusts_page_state() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = *SLAB else { return };
        unsafe {
            let words = slab as *mut u32;
            core::ptr::write_bytes(words, 0, SLAB_LEN / core::mem::size_of::<u32>());
            let destination = words.add(0x100);
            let source = words.add(0x300);
            let destination_transition = words.add(0x700);
            let source_transition = words.add(0x780);
            *destination.add(TRANSITION_OFFSET / 4) = destination_transition as usize as u32;
            *source.add(TRANSITION_OFFSET / 4) = source_transition as usize as u32;
            *source_transition.add(7) = 0x1234_5678;
            for offset in [8, 0x50] {
                for word in 0..18 {
                    *source.add(offset / 4 + word) = 0x1000 + offset as u32 + word as u32;
                    *destination.add(offset / 4 + word) = 0xdead_0000 + word as u32;
                }
            }
            *source.add(0x0c / 4) = 0xfff0_0000;
            *source.add(PAGE_STATE_OFFSET / 4) = 0x0001_0000;
            for offset in [0x164, 0x188, 0x1ac, 0x1d0, 0x1f4] {
                *source.add(offset / 4) = 0xabcd_0000 + offset as u32;
            }
            transition_page_clone(destination, source, -2, 0);
            assert_eq!(*destination.add(0x0c / 4), 0xffd2_0000);
            assert_eq!(*destination.add(0x10 / 4), 0);
            assert_eq!(*destination.add(PAGE_STATE_OFFSET / 4), 0xffe3_0000);
            assert_eq!(*destination_transition.add(7), 0x1234_5678);
            assert_eq!(*destination_transition.add(8), 1000);
            for offset in [8, 0x50] {
                for word in 1..6 {
                    if offset == 8 && (word == 1 || word == 2) {
                        continue;
                    }
                    assert_eq!(*destination.add(offset / 4 + word), *source.add(offset / 4 + word));
                }
            }
            for offset in [0x164, 0x188, 0x1ac, 0x1d0, 0x1f4] {
                assert_eq!(*destination.add(offset / 4), *source.add(offset / 4));
            }
        }
    }
}
