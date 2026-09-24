//! `sixteen_resource_slots_destroy` — release an owner with sixteen resource slots.
//!
//! Original: `FUN_08086a88` @ 0x08086a88 (80 bytes exactly,
//! 0x08086a88..0x08086ad8; the next independently linked function starts at
//! 0x08086ad8). Raw ARM words contain one plain `bl traced_free`, no predicated
//! `bl`, and a final tail `b traced_free`. There are three plain inbound `bl`
//! call sites and no predicated inbound calls.
//!
//! Algorithm: return for NULL; for slots 0 through 15, release a nonzero
//! resource at +0x44 through `traced_free` when the matching +0x84 flag word
//! has bit 0 set, then clear both words. Finally release the owner itself.
//!
//! Deliberate deviation: the retail final tail branch to `traced_free` is an
//! ordinary returning Rust call. `traced_free` returns normally, so observable
//! behavior is unchanged.

use crate::drivers::ata_cmd::traced_free;

/// Target-layout prefix inspected by [`sixteen_resource_slots_destroy`].
#[repr(C)]
pub struct SixteenResourceSlots {
    /// +0x00..+0x40: fields not inspected by this destructor.
    pub reserved: [u32; 17],
    /// +0x44..+0x80: resource pointer words.
    pub resources: [u32; 16],
    /// +0x84..+0xc0: ownership flags paired with [`Self::resources`].
    pub flags: [u32; 16],
}

const _: [u8; 0x44] = [0; core::mem::offset_of!(SixteenResourceSlots, resources)];
const _: [u8; 0x84] = [0; core::mem::offset_of!(SixteenResourceSlots, flags)];
const _: [u8; 0xc4] = [0; core::mem::size_of::<SixteenResourceSlots>()];

/// (80 bytes; 1 plain `bl`, 0 predicated `bl`, and one tail `b`.)
///
/// Releases flagged nonzero resource slots in ascending index order, clears all
/// sixteen resource/flag pairs, then releases `this`. The caller must provide
/// NULL or a writable, aligned object with the displayed target-layout prefix;
/// every released resource must belong to `traced_free`'s allocation family.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sixteen_resource_slots_destroy(this: *mut SixteenResourceSlots) {
    if this.is_null() {
        return;
    }

    for index in 0..16 {
        let resource = unsafe { core::ptr::addr_of!((*this).resources[index]).read_volatile() };
        if resource != 0 {
            let flags = unsafe { core::ptr::addr_of!((*this).flags[index]).read_volatile() };
            if flags & 1 != 0 {
                unsafe { traced_free(resource as usize as *mut u8) };
            }
        }
        unsafe {
            core::ptr::addr_of_mut!((*this).resources[index]).write_volatile(0);
            core::ptr::addr_of_mut!((*this).flags[index]).write_volatile(0);
        }
    }

    unsafe { traced_free(this.cast::<u8>()) };
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

    unsafe fn restore(guard: MutexGuard<'static, ()>, alloc_guard: MutexGuard<'static, ()>, old: TracedFreeHooks) {
        unsafe { TRACED_FREE_HOOKS = old };
        drop(guard);
        drop(alloc_guard);
    }

    #[test]
    fn null_owner_does_not_call_allocator() {
        let (guard, alloc_guard, old) = install();
        unsafe { sixteen_resource_slots_destroy(core::ptr::null_mut()) };
        assert!(unsafe { (*core::ptr::addr_of!(FREED)).is_empty() });
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn frees_only_flagged_resources_then_clears_all_slots_and_owner() {
        let (guard, alloc_guard, old) = install();
        let mut owner = SixteenResourceSlots {
            reserved: [0x1122_3344; 17],
            resources: [0; 16],
            flags: [0; 16],
        };
        let first = crate::testing::try_map_u32_slab(crate::testing::hints::SIXTEEN_RESOURCE_SLOTS_DESTROY, 0x1000);
        if first.is_none() {
            unsafe { restore(guard, alloc_guard, old) };
            assert!(crate::testing::note_missing_u32_fixture("heap::sixteen_resource_slots"));
            return;
        }
        let first = first.unwrap();
        owner.resources[0] = first as usize as u32;
        owner.flags[0] = 1;
        owner.resources[1] = (first as usize + 4) as u32;
        owner.flags[1] = 2;
        owner.resources[15] = (first as usize + 8) as u32;
        owner.flags[15] = 3;
        let this = &mut owner as *mut SixteenResourceSlots;

        unsafe { sixteen_resource_slots_destroy(this) };

        assert_eq!(unsafe { (*core::ptr::addr_of!(FREED)).clone() }, std::vec![first as usize, first as usize + 8, this as usize]);
        assert_eq!(owner.resources, [0; 16]);
        assert_eq!(owner.flags, [0; 16]);
        assert_eq!(owner.reserved, [0x1122_3344; 17]);
        unsafe { restore(guard, alloc_guard, old) };
    }
}
