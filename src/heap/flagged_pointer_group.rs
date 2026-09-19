//! `flagged_pointer_group_destroy` — release an optionally owned pointer group.
//!
//! Original: `FUN_0803a168` @ 0x0803a168 (116 bytes exactly,
//! 0x0803a168..0x0803a1dc; the allocation factory starts at 0x0803a1dc).
//! Decoding the raw ARM words finds no plain `bl`, three predicated `blne`
//! instructions to `traced_free`, and one predicated `bne` tail branch to the
//! same callee. The inbound direct-call scan finds four plain `bl` call sites.
//!
//! Algorithm: return for NULL; load flags before each stage; bit 2 frees and
//! clears `first` then `second`; bit 3 frees and clears `auxiliary`, then clears
//! its associated word; bit 0 releases the owner itself.
//!
//! Deliberate deviation: the retail final `bne traced_free` tail branch is an
//! ordinary returning Rust call. `traced_free` returns, so behavior is unchanged.

use crate::drivers::ata_cmd::traced_free;

/// Bit 0: release the owner after its owned fields.
pub const FLAG_DELETE_THIS: u32 = 1;
/// Bit 2: `first` and `second` are owned.
pub const FLAG_OWNS_FIRST_PAIR: u32 = 4;
/// Bit 3: `auxiliary` and its associated word are owned.
pub const FLAG_OWNS_AUXILIARY: u32 = 8;

/// Target-layout group of conditionally owned pointer words.
#[repr(C)]
pub struct FlaggedPointerGroup {
    /// +0x00: first conditionally owned allocation.
    pub first: u32,
    /// +0x04: second conditionally owned allocation.
    pub second: u32,
    /// +0x08: not inspected by this destructor.
    pub reserved: u32,
    /// +0x0c: associated with `auxiliary`.
    pub auxiliary_associated: u32,
    /// +0x10: conditionally owned allocation.
    pub auxiliary: u32,
    /// +0x14: ownership flags.
    pub flags: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(FlaggedPointerGroup, flags)];
const _: [u8; 0x18] = [0; core::mem::size_of::<FlaggedPointerGroup>()];

/// Releases the fields selected by `flags`, then releases `this` when bit 0 is
/// set. `this` must be NULL or a writable, aligned target-layout object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn flagged_pointer_group_destroy(this: *mut FlaggedPointerGroup) {
    if this.is_null() {
        return;
    }

    let flags = unsafe { core::ptr::addr_of!((*this).flags).read_volatile() };
    if flags & FLAG_OWNS_FIRST_PAIR != 0 {
        unsafe {
            let first = (*this).first;
            if first != 0 {
                traced_free(first as usize as *mut u8);
            }
            let second = (*this).second;
            if second != 0 {
                traced_free(second as usize as *mut u8);
            }
            (*this).second = 0;
            (*this).first = 0;
        }
    }

    let flags = unsafe { core::ptr::addr_of!((*this).flags).read_volatile() };

    if flags & FLAG_OWNS_AUXILIARY != 0 {
        unsafe {
            let auxiliary = (*this).auxiliary;
            if auxiliary != 0 {
                traced_free(auxiliary as usize as *mut u8);
            }
            (*this).auxiliary = 0;
            (*this).auxiliary_associated = 0;
        }
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
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut FREED: Vec<usize> = Vec::new();
    static mut FLAGS_TO_CLEAR: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn mock_free(block: *mut u8) {
        unsafe {
            (*core::ptr::addr_of_mut!(FREED)).push(block as usize);
            if !FLAGS_TO_CLEAR.is_null() {
                FLAGS_TO_CLEAR.write(0);
            }
        };
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

    unsafe fn restore(guard: MutexGuard<'static, ()>, alloc_guard: MutexGuard<'static, ()>, old: TracedFreeHooks) {
        unsafe { TRACED_FREE_HOOKS = old };
            FLAGS_TO_CLEAR = core::ptr::null_mut();
        drop(guard);
        drop(alloc_guard);
    }

    fn freed() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(FREED)).clone() }
    }

    #[test]
    fn null_is_a_no_op() {
        let (guard, alloc_guard, old) = install();
        unsafe { flagged_pointer_group_destroy(core::ptr::null_mut()) };
        assert!(freed().is_empty());
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn releases_selected_fields_in_retail_order_then_owner() {
        let (guard, alloc_guard, old) = install();
        let mut group = FlaggedPointerGroup {
            first: 0x1010,
            second: 0x2020,
            reserved: 0x3030,
            auxiliary_associated: 0x4040,
            auxiliary: 0x5050,
            flags: FLAG_OWNS_FIRST_PAIR | FLAG_OWNS_AUXILIARY | FLAG_DELETE_THIS,
        };
        let this = &mut group as *mut FlaggedPointerGroup;

        unsafe { flagged_pointer_group_destroy(this) };

        assert_eq!(freed(), std::vec![0x1010, 0x2020, 0x5050, this as usize]);
        assert_eq!(group.first, 0);
        assert_eq!(group.second, 0);
        assert_eq!(group.auxiliary, 0);
        assert_eq!(group.auxiliary_associated, 0);
        assert_eq!(group.reserved, 0x3030);
        assert_eq!(group.flags, FLAG_OWNS_FIRST_PAIR | FLAG_OWNS_AUXILIARY | FLAG_DELETE_THIS);
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn inactive_ownership_bits_leave_fields_untouched() {
        let (guard, alloc_guard, old) = install();
        let mut group = FlaggedPointerGroup {
            first: 0x1010,
            second: 0x2020,
            reserved: 0x3030,
            auxiliary_associated: 0x4040,
            auxiliary: 0x5050,
            flags: 0,
        };

        unsafe { flagged_pointer_group_destroy(&mut group) };

        assert!(freed().is_empty());
        assert_eq!(group.first, 0x1010);
        assert_eq!(group.second, 0x2020);
        assert_eq!(group.auxiliary_associated, 0x4040);
        assert_eq!(group.auxiliary, 0x5050);
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn reloads_flags_after_releasing_first_pair() {
        let (guard, alloc_guard, old) = install();
        let mut group = FlaggedPointerGroup {
            first: 0x1010,
            second: 0x2020,
            reserved: 0x3030,
            auxiliary_associated: 0x4040,
            auxiliary: 0x5050,
            flags: FLAG_OWNS_FIRST_PAIR | FLAG_OWNS_AUXILIARY | FLAG_DELETE_THIS,
        };
        unsafe { FLAGS_TO_CLEAR = core::ptr::addr_of_mut!(group.flags) };

        unsafe { flagged_pointer_group_destroy(&mut group) };

        assert_eq!(freed(), std::vec![0x1010, 0x2020]);
        assert_eq!(group.first, 0);
        assert_eq!(group.second, 0);
        assert_eq!(group.auxiliary_associated, 0x4040);
        assert_eq!(group.auxiliary, 0x5050);
        unsafe { restore(guard, alloc_guard, old) };
    }
}
