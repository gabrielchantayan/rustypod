//! Drawable-owner surface swap and pixel preservation.
//!
//! `FUN_0828c684` @ 0x0828c684: 124 bytes, ending with the memcpy tail
//! branch at 0x0828c6fc; the next real function starts at 0x0828c700.
//! Raw ARM words contain one plain BL (rect_height), one predicated BLNE
//! (0x081066e8), and one unconditional tail B to 0x08037db0.
//! Requires both surfaces (+0x54/+0x58) and the child (+0x78). Selects the
//! second surface if the current surface is the first, otherwise selects the
//! first; mirrors its associated state (+0x48/+0x4c) into +0x50. If +0xf8
//! is nonzero, waits on that selected state before copying the previous
//! surface's pixels into the new one. Length is first-surface stride (+8)
//! times its rectangle height (+0x98), with wrapping 32-bit arithmetic.
//!
//! Deliberate deviations: calls the existing Rust rect_height and __rt_memcpy
//! ports instead of their retail entries. The unported 0x081066e8 helper
//! locks state+0x40, waits on state+0x48 until byte +0x3d is nonzero, then
//! unlocks; its verified-address volatile seam is replaceable on hosts.
//! Pointer fields remain target-width words on every platform.

use core::ptr;
use crate::ui::rect::{rect_height, Rect};
use crate::libc::rt_memcpy::__rt_memcpy;

pub type SurfaceStateWaitReady = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_wait_ready(state: *mut u8) {
    let wait: SurfaceStateWaitReady = core::mem::transmute(0x0810_66e8usize);
    wait(state);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_wait_ready(_state: *mut u8) {
    panic!("surface state wait requires a host implementation");
}

pub static mut SURFACE_STATE_WAIT_READY: SurfaceStateWaitReady = retail_wait_ready;

#[inline(always)]
unsafe fn word(object: *mut u8, offset: usize) -> u32 {
    object.add(offset).cast::<u32>().read()
}

/// # Safety
/// Owner must be aligned and readable through +0xf8. On the active path,
/// current and selected surfaces and their state objects must be valid;
/// pixel buffers must satisfy __rt_memcpy's non-overlapping padded contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn coordinate_owner_swap_surface(owner: *mut u8) {
    let first = word(owner, 0x54);
    if first == 0 { return; }
    let second = word(owner, 0x58);
    if second == 0 || word(owner, 0x78) == 0 { return; }
    let previous = word(owner, 0x5c);
    let selected = if previous == first { second } else { first };
    owner.add(0x5c).cast::<u32>().write(selected);
    let state = word(owner, if selected == first { 0x48 } else { 0x4c });
    owner.add(0x50).cast::<u32>().write(state);
    if owner.add(0xf8).read() != 0 {
        let wait = ptr::addr_of!(SURFACE_STATE_WAIT_READY).read_volatile();
        wait(state as usize as *mut u8);
    }
    // The wait can change owner fields: preserve the original reload order.
    let first = word(owner, 0x54) as usize as *mut u8;
    let height = rect_height(first.add(0x98).cast::<Rect>()) as u32;
    let first = word(owner, 0x54) as usize as *mut u8;
    let len = word(first, 8).wrapping_mul(height);
    let selected = word(owner, 0x5c) as usize as *mut u8;
    let src = word(previous as usize as *mut u8, 4) as usize as *const u8;
    let dst = word(selected, 4) as usize as *mut u8;
    __rt_memcpy(dst, src, len as usize);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::LazyLock;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<usize> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::COORDINATE_OWNER_SWAP_SURFACE, 0x1000)
            .expect("low-address surface fixture") as usize
    });
    unsafe fn put(base: *mut u8, offset: usize, value: u32) {
        base.add(offset).cast::<u32>().write(value);
    }
    unsafe fn fixture() -> (*mut u8, *mut u8, *mut u8) {
        let owner = *SLAB as *mut u8;
        owner.write_bytes(0, 0x1000);
        let first = owner.add(0x200);
        let second = owner.add(0x400);
        put(owner, 0x54, first as u32);
        put(owner, 0x58, second as u32);
        put(owner, 0x78, 1);
        put(owner, 0x48, owner.add(0x800) as u32);
        put(owner, 0x4c, owner.add(0x900) as u32);
        put(first, 4, owner.add(0x600) as u32);
        put(second, 4, owner.add(0x700) as u32);
        put(first, 8, 3);
        put(first, 0x98, 7);
        put(first, 0xa0, 9);
        for i in 0..32 { owner.add(0x600 + i).write(i as u8 + 1); }
        owner.add(0x700).write_bytes(0xaa, 32);
        (owner, first, second)
    }
    #[test]
    fn swaps_both_directions_and_copies_exact_stride_times_height() {
        let _lock = LOCK.lock();
        unsafe {
            let (owner, first, second) = fixture();
            put(owner, 0x5c, first as u32);
            coordinate_owner_swap_surface(owner);
            assert_eq!(word(owner, 0x5c), second as u32);
            assert_eq!(word(owner, 0x50), word(owner, 0x4c));
            assert_eq!(core::slice::from_raw_parts(owner.add(0x700), 8), &[1,2,3,4,5,6,0xaa,0xaa]);
            owner.add(0x700).write(99);
            coordinate_owner_swap_surface(owner);
            assert_eq!(word(owner, 0x5c), first as u32);
            assert_eq!(word(owner, 0x50), word(owner, 0x48));
            assert_eq!(owner.add(0x600).read(), 99);
        }
    }
    #[test]
    fn each_missing_prerequisite_leaves_selection_and_pixels_unchanged() {
        let _lock = LOCK.lock();
        unsafe {
            for offset in [0x54, 0x58, 0x78] {
                let (owner, first, _) = fixture();
                put(owner, 0x5c, first as u32);
                put(owner, 0x50, 0xdeadbeef);
                put(owner, offset, 0);
                coordinate_owner_swap_surface(owner);
                assert_eq!(word(owner, 0x5c), first as u32);
                assert_eq!(word(owner, 0x50), 0xdeadbeef);
                assert_eq!(owner.add(0x700).read(), 0xaa);
            }
        }
    }
    unsafe extern "C" fn ready(state: *mut u8) {
        let owner = *SLAB as *mut u8;
        assert_eq!(state, owner.add(0x900));
        assert_eq!(word(owner, 0x50), state as u32);
        assert_eq!(word(owner, 0x5c), owner.add(0x400) as u32);
        // Completion changes the stride and pixels before the copy.
        put(owner.add(0x200), 8, 2);
        owner.add(0x600).write(77);
    }
    #[test]
    fn waits_after_selection_and_reloads_copy_parameters() {
        let _lock = LOCK.lock();
        unsafe {
            let (owner, first, _) = fixture();
            put(owner, 0x5c, first as u32);
            owner.add(0xf8).write(0x80);
            let saved = SURFACE_STATE_WAIT_READY;
            SURFACE_STATE_WAIT_READY = ready;
            coordinate_owner_swap_surface(owner);
            SURFACE_STATE_WAIT_READY = saved;
            assert_eq!(core::slice::from_raw_parts(owner.add(0x700), 6), &[77,2,3,4,0xaa,0xaa]);
        }
    }
    #[test]
    fn third_current_surface_selects_first_and_zero_height_copies_nothing() {
        let _lock = LOCK.lock();
        unsafe {
            let (owner, first, _) = fixture();
            let third = owner.add(0xa00);
            put(third, 4, owner.add(0xb00) as u32);
            put(owner, 0x5c, third as u32);
            put(first, 0xa0, 7);
            coordinate_owner_swap_surface(owner);
            assert_eq!(word(owner, 0x5c), first as u32);
            assert_eq!(word(owner, 0x50), word(owner, 0x48));
            assert_eq!(owner.add(0x600).read(), 1);
        }
    }
}
