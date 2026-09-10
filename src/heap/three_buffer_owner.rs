//! `three_buffer_owner_release` — destroy an owner of three releasable buffers.
//!
//! Original: `FUN_0803deec` @ 0x0803deec (60 bytes exactly,
//! 0x0803deec..0x0803df28; `FUN_0803df28` starts at the next word, with no
//! trailing literal pool). Decoding every ARM B/BL immediate in `osos.dec`
//! finds 11 direct call sites: eight unconditional `bl` and three `blne`
//! (0x0808777c, 0x08087788, and 0x08087794). The predicated callers check
//! their three individual owner words before releasing them; the body retains
//! its own NULL guard.
//!
//! Algorithm: return for NULL; release the embedded `ReleasableBuffer`s at
//! +0x04, +0x18, and +0x2c in that order; then release the owner through
//! `traced_free` when its +0x44 flags word has bit 0 set.
//!
//! Deliberate deviations: the retail final `b traced_free` tail branch is an
//! ordinary returning Rust call. `traced_free` returns normally, so observable
//! behavior is unchanged.

use crate::drivers::ata_cmd::traced_free;
use crate::heap::releasable_buffer::{releasable_buffer_release, ReleasableBuffer};

/// `flags` bit 0: release the owner after its embedded buffers.
pub const FLAG_DELETE_THIS: u32 = 1;

/// Target-layout owner of three independently releasable buffers.
#[repr(C)]
pub struct ThreeBufferOwner {
    /// +0x00: field not inspected by this destructor.
    pub reserved: u32,
    /// +0x04: first embedded buffer.
    pub first: ReleasableBuffer,
    /// +0x18: second embedded buffer.
    pub second: ReleasableBuffer,
    /// +0x2c: third embedded buffer.
    pub third: ReleasableBuffer,
    /// +0x40: field not inspected by this destructor.
    pub trailing: u32,
    /// +0x44: ownership flags for the outer object.
    pub flags: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(ThreeBufferOwner, first)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(ThreeBufferOwner, second)];
const _: [u8; 0x2c] = [0; core::mem::offset_of!(ThreeBufferOwner, third)];
const _: [u8; 0x44] = [0; core::mem::offset_of!(ThreeBufferOwner, flags)];
const _: [u8; 0x48] = [0; core::mem::size_of::<ThreeBufferOwner>()];

/// (60 bytes; 8 `bl` and 3 `blne` direct call sites.)
///
/// Releases the three embedded buffers in target offset order, then releases
/// `this` if its flag bit 0 is set. The caller must provide NULL or a writable,
/// aligned [`ThreeBufferOwner`]; each embedded buffer has the ownership
/// contract of [`releasable_buffer_release`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn three_buffer_owner_release(this: *mut ThreeBufferOwner) {
    if this.is_null() {
        return;
    }

    unsafe {
        releasable_buffer_release(core::ptr::addr_of_mut!((*this).first));
        releasable_buffer_release(core::ptr::addr_of_mut!((*this).second));
        releasable_buffer_release(core::ptr::addr_of_mut!((*this).third));
    }

    let flags = unsafe { core::ptr::addr_of!((*this).flags).read_volatile() };
    if flags & FLAG_DELETE_THIS != 0 {
        unsafe { traced_free(this.cast::<u8>()) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS};
    use crate::heap::releasable_buffer::{FLAG_BUFFER_BORROWED, FLAG_RELEASED};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut FREED: Vec<usize> = Vec::new();

    unsafe extern "C" fn mock_free(block: *mut u8) {
        unsafe { (*core::ptr::addr_of_mut!(FREED)).push(block as usize) };
    }

    fn install() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, TracedFreeHooks) {
        let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let old = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS));
            TRACED_FREE_HOOKS = TracedFreeHooks { free: mock_free, trace: None };
            (*core::ptr::addr_of_mut!(FREED)).clear();
            (guard, alloc_guard, old)
        }
    }

    unsafe fn restore(
        guard: MutexGuard<'static, ()>,
        alloc_guard: MutexGuard<'static, ()>,
        old: TracedFreeHooks,
    ) {
        unsafe { TRACED_FREE_HOOKS = old };
        drop(guard);
        drop(alloc_guard);
    }

    fn freed() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(FREED)).clone() }
    }

    /// Unique low-address mapping because each embedded `data` field is a
    /// target-width pointer word. The mapper deliberately never unmaps.
    fn try_data() -> Option<*mut u8> {
        static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::THREE_BUFFER_OWNER_RELEASE, 0x1000)
                .map(|pointer| pointer as usize)
        });
        (*SLAB).map(|pointer| pointer as *mut u8)
    }

    fn fixture_unavailable() -> bool {
        try_data().is_none() && crate::testing::note_missing_u32_fixture("heap::three_buffer_owner")
    }

    fn buffer(data: u32, flags: u32) -> ReleasableBuffer {
        ReleasableBuffer { data, reserved: [0; 3], flags }
    }

    #[test]
    fn null_owner_does_not_call_allocator() {
        let (guard, alloc_guard, old) = install();
        unsafe { three_buffer_owner_release(core::ptr::null_mut()) };
        assert!(freed().is_empty());
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn releases_embedded_buffers_in_order_then_owner() {
        if fixture_unavailable() {
            return;
        }
        let (guard, alloc_guard, old) = install();
        let data = try_data().unwrap();
        let mut owner = ThreeBufferOwner {
            reserved: 0x1111_1111,
            first: buffer(data as usize as u32, 0),
            second: buffer((data as usize + 4) as u32, FLAG_BUFFER_BORROWED),
            third: buffer(0, 0x40),
            trailing: 0x2222_2222,
            flags: FLAG_DELETE_THIS,
        };
        let this = &mut owner as *mut ThreeBufferOwner;

        unsafe { three_buffer_owner_release(this) };

        assert_eq!(freed(), std::vec![data as usize, this as usize]);
        assert_eq!(owner.first.flags, FLAG_RELEASED);
        assert_eq!(owner.second.flags, FLAG_BUFFER_BORROWED | FLAG_RELEASED);
        assert_eq!(owner.third.flags, 0x8040);
        assert_eq!(owner.first.data, data as usize as u32, "retail code leaves freed data dangling");
        assert_eq!(owner.second.data, (data as usize + 4) as u32);
        assert_eq!(owner.reserved, 0x1111_1111);
        assert_eq!(owner.trailing, 0x2222_2222);
        assert_eq!(owner.flags, FLAG_DELETE_THIS, "outer flags are only read");
        unsafe { restore(guard, alloc_guard, old) };
    }
}
