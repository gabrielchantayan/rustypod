//! `two_buffer_owner_release` — destroy an owner of two releasable buffer pointers.
//!
//! Original: `FUN_0803dba8` @ 0x0803dba8 (48 bytes exactly,
//! 0x0803dba8..0x0803dbd8; `FUN_0803dbd8` starts at the next word, with no
//! trailing literal pool). Ghidra reports 48 bytes, which matches the raw
//! extent. Decoding every ARM B/BL immediate in `osos.dec` finds exactly 5
//! direct call sites, matching Ghidra's count: two unconditional `bl`
//! (0x0803dcf4, 0x08062248) and three `blne` (0x0806242c, 0x080cbae0,
//! 0x080cbe24). The predicated callers gate the call on their own owner word
//! being non-NULL; the body retains its own NULL guard.
//!
//! ```text
//! 0803dba8:  stmdb sp!,{r4,lr}
//! 0803dbac:  movs r4,r0
//! 0803dbb0:  ldmiaeq sp!,{r4,pc}        ; if (this == NULL) return
//! 0803dbb4:  ldr r0,[r4,#0x4]
//! 0803dbb8:  cmp r0,#0x0
//! 0803dbbc:  blne releasable_buffer_release   ; 0x0803eee4
//! 0803dbc0:  ldr r0,[r4,#0x8]
//! 0803dbc4:  cmp r0,#0x0
//! 0803dbc8:  blne releasable_buffer_release   ; 0x0803eee4
//! 0803dbcc:  mov r0,r4
//! 0803dbd0:  ldmia sp!,{r4,lr}
//! 0803dbd4:  b traced_free                    ; 0x08043994
//! ```
//!
//! Algorithm: return for NULL; release the buffer pointer at +0x04 when
//! non-NULL, then the buffer pointer at +0x08 when non-NULL; finally release
//! the owner itself through `traced_free` unconditionally. Unlike
//! [`crate::heap::three_buffer_owner`], the buffers are heap pointers rather
//! than embedded and there is no outer flags gate on the final free.
//!
//! Deliberate deviation: the retail final `b traced_free` tail branch is an
//! ordinary returning Rust call. `traced_free` returns normally, so observable
//! behavior is unchanged.

use crate::drivers::ata_cmd::traced_free;
use crate::heap::releasable_buffer::{releasable_buffer_release, ReleasableBuffer};

/// Target-layout owner of two independently releasable buffer pointers, as
/// allocated by the paired create function `FUN_0803dc50` (0x14 bytes).
#[repr(C)]
pub struct TwoBufferOwner {
    /// +0x00: field not inspected by this destructor.
    pub reserved: u32,
    /// +0x04: first buffer pointer, NULL when absent.
    pub first: u32,
    /// +0x08: second buffer pointer, NULL when absent.
    pub second: u32,
    /// +0x0c..+0x10: fields not inspected by this destructor.
    pub trailing: [u32; 2],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(TwoBufferOwner, first)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(TwoBufferOwner, second)];
const _: [u8; 0x14] = [0; core::mem::size_of::<TwoBufferOwner>()];

/// (48 bytes; 2 `bl` and 3 `blne` direct call sites.)
///
/// Releases the two non-NULL buffer pointers in target offset order, then
/// releases `this` through `traced_free`. The caller must provide NULL or a
/// readable, aligned [`TwoBufferOwner`]; each non-NULL buffer pointer has the
/// ownership contract of [`releasable_buffer_release`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn two_buffer_owner_release(this: *mut TwoBufferOwner) {
    if this.is_null() {
        return;
    }

    let first = unsafe { core::ptr::addr_of!((*this).first).read_volatile() };
    if first != 0 {
        unsafe { releasable_buffer_release(first as *mut ReleasableBuffer) };
    }

    let second = unsafe { core::ptr::addr_of!((*this).second).read_volatile() };
    if second != 0 {
        unsafe { releasable_buffer_release(second as *mut ReleasableBuffer) };
    }

    unsafe { traced_free(this.cast::<u8>()) };
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

    /// Unique low-address mapping because each buffer pointer and each
    /// embedded `data` field is a target-width pointer word. The mapper
    /// deliberately never unmaps. Layout: two `ReleasableBuffer`s at +0x00
    /// and +0x14, then two spare data words at +0x28 and +0x2c.
    fn try_slab() -> Option<*mut u8> {
        static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::TWO_BUFFER_OWNER_RELEASE, 0x1000)
                .map(|pointer| pointer as usize)
        });
        (*SLAB).map(|pointer| pointer as *mut u8)
    }

    fn fixture_unavailable() -> bool {
        try_slab().is_none() && crate::testing::note_missing_u32_fixture("heap::two_buffer_owner")
    }

    #[test]
    fn null_owner_does_not_call_allocator() {
        let (guard, alloc_guard, old) = install();
        unsafe { two_buffer_owner_release(core::ptr::null_mut()) };
        assert!(freed().is_empty());
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn null_buffers_free_only_the_owner() {
        let (guard, alloc_guard, old) = install();
        let mut owner = TwoBufferOwner { reserved: 0x1111_1111, first: 0, second: 0, trailing: [0x2222_2222; 2] };
        let this = &mut owner as *mut TwoBufferOwner;

        unsafe { two_buffer_owner_release(this) };

        assert_eq!(freed(), std::vec![this as usize]);
        assert_eq!(owner.reserved, 0x1111_1111, "unread fields are untouched");
        assert_eq!(owner.trailing, [0x2222_2222; 2]);
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn releases_pointed_buffers_in_order_then_owner() {
        if fixture_unavailable() {
            return;
        }
        let (guard, alloc_guard, old) = install();
        let slab = try_slab().unwrap();
        let first = slab as *mut ReleasableBuffer;
        let second = unsafe { slab.add(0x14) } as *mut ReleasableBuffer;
        let data_a = unsafe { slab.add(0x28) } as usize as u32;
        let data_b = unsafe { slab.add(0x2c) } as usize as u32;
        unsafe {
            first.write(ReleasableBuffer { data: data_a, reserved: [0; 3], flags: 0 });
            second.write(ReleasableBuffer { data: data_b, reserved: [0; 3], flags: FLAG_BUFFER_BORROWED });
        }
        let mut owner = TwoBufferOwner {
            reserved: 0,
            first: first as usize as u32,
            second: second as usize as u32,
            trailing: [0; 2],
        };
        let this = &mut owner as *mut TwoBufferOwner;

        unsafe { two_buffer_owner_release(this) };

        assert_eq!(freed(), std::vec![data_a as usize, this as usize]);
        assert_eq!(unsafe { (*first).flags }, FLAG_RELEASED);
        assert_eq!(unsafe { (*second).flags }, FLAG_BUFFER_BORROWED | FLAG_RELEASED);
        assert_eq!(unsafe { (*first).data }, data_a, "retail code leaves freed data dangling");
        assert_eq!(unsafe { (*second).data }, data_b, "borrowed data never reaches traced_free");
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn second_null_still_releases_first_then_owner() {
        if fixture_unavailable() {
            return;
        }
        let (guard, alloc_guard, old) = install();
        let slab = try_slab().unwrap();
        let first = slab as *mut ReleasableBuffer;
        unsafe { first.write(ReleasableBuffer { data: 0, reserved: [0; 3], flags: 0 }) };
        let mut owner = TwoBufferOwner { reserved: 0, first: first as usize as u32, second: 0, trailing: [0; 2] };
        let this = &mut owner as *mut TwoBufferOwner;

        unsafe { two_buffer_owner_release(this) };

        assert_eq!(freed(), std::vec![this as usize], "NULL data frees nothing; owner always freed");
        assert_eq!(unsafe { (*first).flags }, FLAG_RELEASED);
        unsafe { restore(guard, alloc_guard, old) };
    }
}
