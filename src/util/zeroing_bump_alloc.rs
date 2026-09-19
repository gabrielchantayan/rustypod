//! `zeroing_bump_alloc` — original: `FUN_08057184` @ `0x08057184` (100 bytes).
//!
//! Raw `osos.dec` words establish the exact extent `0x08057184..0x080571e8`:
//! the final `pop {r4,pc}` is at `0x080571e4` and the following word is the
//! literal `0x08b2f7e8`, not code. The next separately entered function begins
//! at `0x080571ec`. A whole-image A32 decode finds four inbound plain `bl`
//! sites (`0x08039290`, `0x08057740`, `0x08057820`, and `0x08075f78`) and no
//! predicated inbound calls. The body has no plain outbound `bl` and one
//! predicated `blne`, to the backward zero-fill leaf at `0x08057210`.
//!
//! The global three-word arena state is `{ enabled, cursor, remaining }` at
//! `0x08b2f7e8`. When enabled, it rounds the requested length upward, consumes
//! the cursor's existing misalignment plus that rounded length, rejects a
//! signed `remaining <= consumed` comparison, advances the cursor, and
//! backward-zeroes `consumed` bytes beginning at the aligned return pointer.
//! This intentionally includes alignment slack and therefore is not a normal
//! malloc contract. Deliberate deviation: the zero-fill is local rather than a
//! branch to the separately linked stock leaf, so the relocated Rust payload
//! has no dependency on its fixed retail address.
#[cfg(target_os = "none")]

const ARENA_STATE_ADDRESS: usize = 0x08b2_f7e8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn arena_state() -> *mut u32 {
    ARENA_STATE_ADDRESS as *mut u32
}

#[cfg(not(target_os = "none"))]
pub static mut ZEROING_BUMP_ARENA_STATE: *mut u32 = core::ptr::null_mut();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn arena_state() -> *mut u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(ZEROING_BUMP_ARENA_STATE))
}

#[inline(always)]
unsafe fn zero_backward(dst: *mut u8, mut len: u32) {
    while len != 0 {
        len -= 1;
        dst.add(len as usize).write_volatile(0);
    }
}

/// Allocates and zeroes a block from the enabled global bump arena.
///
/// # Safety
/// The fixed arena state and the range selected by its target-width cursor
/// must be valid. The caller must serialize mutations of that state.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.zeroing_bump_alloc_08057184")]
#[inline(never)]
pub unsafe extern "C" fn zeroing_bump_alloc(requested_len: u32) -> *mut u8 {
    let state = unsafe { arena_state() };
    if unsafe { state.read_volatile() } == 0 {
        return core::ptr::null_mut();
    }

    let rounded_len = requested_len.wrapping_add(3) & !3;
    let cursor = unsafe { state.add(1).read_volatile() };
    let consumed = (cursor & 3).wrapping_add(rounded_len);
    let remaining = unsafe { state.add(2).read_volatile() };
    if (remaining as i32) <= (consumed as i32) {
        return core::ptr::null_mut();
    }

    unsafe {
        state.add(2).write_volatile(remaining.wrapping_sub(consumed));
        state.add(1).write_volatile(cursor.wrapping_add(consumed));
    }
    let allocation = cursor.wrapping_add(3) & !3;
    if allocation != 0 {
        unsafe { zero_backward(allocation as usize as *mut u8, consumed) };
    }
    allocation as usize as *mut u8
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    const SLAB_BYTES: usize = 0x1000;
    const DATA_OFFSET: usize = 0x100;

    struct Restore(*mut u32);

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { ZEROING_BUMP_ARENA_STATE = self.0 };
        }
    }

    fn fixture() -> Option<(*mut u32, *mut u8)> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            try_map_u32_slab(hints::ZEROING_BUMP_ALLOC, SLAB_BYTES).map(|slab| slab as usize)
        });
        let slab = (*SLAB)? as *mut u8;
        Some((slab as *mut u32, unsafe { slab.add(DATA_OFFSET) }))
    }

    unsafe fn install(state: *mut u32) -> Restore {
        let restore = Restore(ZEROING_BUMP_ARENA_STATE);
        ZEROING_BUMP_ARENA_STATE = state;
        restore
    }

    #[test]
    fn aligns_consumes_slack_and_zeros_the_full_consumed_span() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((state, data)) = fixture() else { return };
        unsafe {
            state.write(1);
            state.add(1).write(data.add(1) as usize as u32);
            state.add(2).write(16);
            core::ptr::write_bytes(data, 0xa5, 32);
            let _restore = install(state);

            assert_eq!(zeroing_bump_alloc(5), data.add(4));
            assert_eq!(state.add(1).read(), data.add(10) as usize as u32);
            assert_eq!(state.add(2).read(), 7);
            assert_eq!(&core::slice::from_raw_parts(data, 4), &[0xa5; 4]);
            assert!(core::slice::from_raw_parts(data.add(4), 9).iter().all(|&byte| byte == 0));
            assert_eq!(*data.add(13), 0xa5);
        }
    }

    #[test]
    fn disabled_or_exactly_exhausted_state_leaves_it_unchanged() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((state, data)) = fixture() else { return };
        unsafe {
            state.write(0);
            state.add(1).write(data as usize as u32);
            state.add(2).write(9);
            let _restore = install(state);
            assert!(zeroing_bump_alloc(4).is_null());
            assert_eq!([state.read(), state.add(1).read(), state.add(2).read()], [0, data as usize as u32, 9]);

            state.write(1);
            state.add(2).write(4);
            assert!(zeroing_bump_alloc(4).is_null());
            assert_eq!([state.read(), state.add(1).read(), state.add(2).read()], [1, data as usize as u32, 4]);
        }
    }
}
