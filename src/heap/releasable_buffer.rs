//! `releasable_buffer_release` — release owned data from a five-word buffer.
//!
//! Original: `FUN_0803eee4` @ 0x0803eee4 (68 bytes exactly,
//! 0x0803eee4..0x0803ef28; `FUN_0803ef28` begins at the next word, so there
//! is no trailing literal pool). Decoding every ARM B/BL immediate in
//! `osos.dec` finds 17 direct call sites: 10 unconditional `bl`, 3 `blne`,
//! and 4 `bleq`. The predicated callers gate release on their own flags or
//! NULL checks; this function still has its own NULL guard.
//!
//! Algorithm:
//!
//! 1. NULL `this` returns without touching allocator state.
//! 2. A non-NULL `data` word is released through `traced_free` unless flags
//!    bit 1 says the buffer is borrowed.
//! 3. Flags are reloaded after that call, then bit 15 is set. If the reloaded
//!    flags have bit 0 set, `this` is released through `traced_free`. The data
//!    word intentionally remains unchanged, so calling this twice releases
//!    owned storage twice; the retail body has the same behavior.
//!
//! Deliberate deviation: the retail `bne traced_free(this)` tail branch is an
//! ordinary returning Rust call. `traced_free` returns normally, so this does
//! not change observable behavior.

use crate::drivers::ata_cmd::traced_free;

/// `flags` bit 0: release `this` after processing its data.
pub const FLAG_DELETE_THIS: u32 = 1;
/// `flags` bit 1: `data` is borrowed and must not reach `traced_free`.
pub const FLAG_BUFFER_BORROWED: u32 = 2;
/// `flags` bit 15: latched by [`releasable_buffer_release`] after processing.
pub const FLAG_RELEASED: u32 = 0x8000;

/// Target-layout five-word buffer header. Only `data` and `flags` are read by
/// this release helper; the three middle words are retained to preserve the
/// verified target offsets.
#[repr(C)]
pub struct ReleasableBuffer {
    /// +0x00: target pointer word for data storage, NULL when absent.
    pub data: u32,
    /// +0x04..+0x0c: fields not inspected by this function.
    pub reserved: [u32; 3],
    /// +0x10: ownership and release-state flags.
    pub flags: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(ReleasableBuffer, data)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(ReleasableBuffer, flags)];
const _: [u8; 0x14] = [0; core::mem::size_of::<ReleasableBuffer>()];

/// (68 bytes; 10 `bl`, 3 `blne`, and 4 `bleq` direct call sites).
///
/// Releases a non-borrowed `data` allocation, marks `flags` released, and
/// releases `this` when bit 0 was set. The caller must provide NULL or a
/// writable, aligned [`ReleasableBuffer`]; each released nonzero word must
/// belong to `traced_free`'s allocation family.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn releasable_buffer_release(this: *mut ReleasableBuffer) {
    if this.is_null() {
        return;
    }

    let data = unsafe { core::ptr::addr_of!((*this).data).read_volatile() };
    let flags = unsafe { core::ptr::addr_of!((*this).flags).read_volatile() };
    if data != 0 && flags & FLAG_BUFFER_BORROWED == 0 {
        unsafe { traced_free(data as usize as *mut u8) };
    }

    // The ARM body reloads +0x10 after the conditional free at 0x0803ef08.
    let flags = unsafe { core::ptr::addr_of!((*this).flags).read_volatile() };
    unsafe { core::ptr::addr_of_mut!((*this).flags).write_volatile(flags | FLAG_RELEASED) };
    if flags & FLAG_DELETE_THIS != 0 {
        unsafe { traced_free(this.cast::<u8>()) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut FREED: Vec<usize> = Vec::new();
    static mut FLAG_TARGET: *mut u32 = core::ptr::null_mut();
    static mut FREE_SET_FLAGS: u32 = 0;

    unsafe extern "C" fn mock_free(block: *mut u8) {
        unsafe {
            (*core::ptr::addr_of_mut!(FREED)).push(block as usize);
            if !FLAG_TARGET.is_null() {
                *FLAG_TARGET |= FREE_SET_FLAGS;
            }
        }
    }

    fn install() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, TracedFreeHooks) {
        let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let old = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS));
            TRACED_FREE_HOOKS = TracedFreeHooks { free: mock_free, trace: None };
            (*core::ptr::addr_of_mut!(FREED)).clear();
            FLAG_TARGET = core::ptr::null_mut();
            FREE_SET_FLAGS = 0;
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

    /// Unique low-address mapping; pointer fields stay `u32` in the target
    /// layout and this mapper deliberately never unmaps.
    fn try_data() -> Option<*mut u8> {
        static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::RELEASABLE_BUFFER, 0x1000)
                .map(|pointer| pointer as usize)
        });
        (*SLAB).map(|pointer| pointer as *mut u8)
    }

    fn fixture_unavailable() -> bool {
        try_data().is_none() && crate::testing::note_missing_u32_fixture("heap::releasable_buffer")
    }

    #[test]
    fn null_this_does_not_call_allocator() {
        let (guard, alloc_guard, old) = install();
        unsafe { releasable_buffer_release(core::ptr::null_mut()) };
        assert!(freed().is_empty());
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn null_data_is_not_freed_but_is_marked_released() {
        let (guard, alloc_guard, old) = install();
        let mut buffer = ReleasableBuffer { data: 0, reserved: [1, 2, 3], flags: 0x40 };

        unsafe { releasable_buffer_release(&mut buffer) };

        assert!(freed().is_empty());
        assert_eq!(buffer.flags, 0x8040);
        assert_eq!(buffer.data, 0);
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn delete_bit_releases_this_after_marking_it() {
        let (guard, alloc_guard, old) = install();
        let mut buffer = ReleasableBuffer { data: 0, reserved: [0; 3], flags: FLAG_DELETE_THIS };
        let this = &mut buffer as *mut ReleasableBuffer;

        unsafe { releasable_buffer_release(this) };

        assert_eq!(freed(), std::vec![this as usize]);
        assert_eq!(buffer.flags, FLAG_DELETE_THIS | FLAG_RELEASED);
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn borrowed_data_is_not_freed() {
        if fixture_unavailable() {
            return;
        }
        let (guard, alloc_guard, old) = install();
        let data = try_data().unwrap();
        let mut buffer = ReleasableBuffer {
            data: data as usize as u32,
            reserved: [0; 3],
            flags: FLAG_BUFFER_BORROWED,
        };

        unsafe { releasable_buffer_release(&mut buffer) };

        assert!(freed().is_empty());
        assert_eq!(buffer.flags, FLAG_BUFFER_BORROWED | FLAG_RELEASED);
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn owned_data_is_freed_and_late_flags_are_reloaded() {
        if fixture_unavailable() {
            return;
        }
        let (guard, alloc_guard, old) = install();
        let data = try_data().unwrap();
        let mut buffer = ReleasableBuffer { data: data as usize as u32, reserved: [0; 3], flags: 0x20 };
        unsafe {
            FLAG_TARGET = core::ptr::addr_of_mut!(buffer.flags);
            FREE_SET_FLAGS = 0x100;
        }

        unsafe { releasable_buffer_release(&mut buffer) };

        assert_eq!(freed(), std::vec![data as usize]);
        assert_eq!(buffer.flags, 0x8120, "reload at 0x0803ef08 observes free-side mutations");
        assert_eq!(buffer.data, data as usize as u32, "the retail code leaves the dangling word intact");
        unsafe { restore(guard, alloc_guard, old) };
    }
}
