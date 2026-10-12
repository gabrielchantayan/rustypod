//! RetailOS media-slot cleanup.
//!
//! `media_slot_release` — `FUN_08044d90` @ `0x08044d90`, **80 bytes**
//! (`0x08044d90..0x08044de0`; the independent `push {r4,lr}` at
//! `0x08044de0` starts the next function). Raw A32 decoding verifies one plain
//! inbound `bl` at `0x08068fb0`, one predicated `blne` at `0x08058748`, and two
//! outbound plain `bl` calls. For slots 0, 1, and 3, release the optional
//! indexed resource at owner+slot*4+0xf8c over [0, u32::MAX], clear that word,
//! then release the optional media allocation at owner+slot*4+0xf7c and clear
//! it. Slot 2 and every slot above 3 are no-ops.
//!
//! Deliberate deviations: the two unported direct callees retain their verified
//! retail entry addresses on ARM and are typed host seams for behavioral tests.
//! Their identities are not recovered beyond their observed release operations.

use core::ptr;

const INDEXED_RESOURCE_OFFSET: usize = 0xf8c;
const MEDIA_ALLOCATION_OFFSET: usize = 0xf7c;

type IndexedResourceRelease = unsafe extern "C" fn(*mut u8, u32, u32);
type MediaAllocationRelease = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_indexed_resource_release(resource: *mut u8, first: u32, last: u32) {
    core::mem::transmute::<usize, IndexedResourceRelease>(0x0806_bf78)(resource, first, last)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_indexed_resource_release(_: *mut u8, _: u32, _: u32) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_media_allocation_release(allocation: *mut u8) {
    core::mem::transmute::<usize, MediaAllocationRelease>(0x0804_90b8)(allocation)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_media_allocation_release(_: *mut u8) {}

/// Unported release operations reached by `media_slot_release`.
#[derive(Clone, Copy)]
pub struct MediaSlotReleaseOps {
    pub indexed_resource_release: IndexedResourceRelease,
    pub media_allocation_release: MediaAllocationRelease,
}

pub static mut MEDIA_SLOT_RELEASE_OPS: MediaSlotReleaseOps = MediaSlotReleaseOps {
    indexed_resource_release: firmware_indexed_resource_release,
    media_allocation_release: firmware_media_allocation_release,
};

/// Releases the two optional allocations associated with a supported media slot.
///
/// # Safety
///
/// `owner` must designate writable target-layout storage through
/// `+0xf98`; both selected fields are aligned four-byte target pointers.
/// Nonzero fields must be valid arguments for the corresponding release seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_slot_release(owner: *mut u8, slot: u32) {
    if slot > 3 || slot == 2 {
        return;
    }

    let slot_offset = slot as usize * 4;
    let indexed_resource_slot = owner.add(INDEXED_RESOURCE_OFFSET + slot_offset).cast::<u32>();
    let media_allocation_slot = owner.add(MEDIA_ALLOCATION_OFFSET + slot_offset).cast::<u32>();
    let ops = ptr::read_volatile(ptr::addr_of!(MEDIA_SLOT_RELEASE_OPS));

    let indexed_resource = indexed_resource_slot.read();
    if indexed_resource != 0 {
        (ops.indexed_resource_release)(indexed_resource as usize as *mut u8, 0, u32::MAX);
        indexed_resource_slot.write(0);
    }

    let media_allocation = media_allocation_slot.read();
    if media_allocation != 0 {
        (ops.media_allocation_release)(media_allocation as usize as *mut u8);
        media_allocation_slot.write(0);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXED_CALL: (*mut u8, u32, u32) = (core::ptr::null_mut(), 1, 0);
    static mut MEDIA_CALL: *mut u8 = core::ptr::null_mut();
    static mut INDEXED_CALLS: u32 = 0;
    static mut MEDIA_CALLS: u32 = 0;

    unsafe extern "C" fn record_indexed(resource: *mut u8, first: u32, last: u32) {
        unsafe {
            INDEXED_CALL = (resource, first, last);
            INDEXED_CALLS += 1;
        }
    }
    unsafe extern "C" fn record_media(allocation: *mut u8) {
        unsafe {
            MEDIA_CALL = allocation;
            MEDIA_CALLS += 1;
        }
    }
    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            INDEXED_CALL = (core::ptr::null_mut(), 1, 0);
            MEDIA_CALL = core::ptr::null_mut();
            INDEXED_CALLS = 0;
            MEDIA_CALLS = 0;
            MEDIA_SLOT_RELEASE_OPS = MediaSlotReleaseOps {
                indexed_resource_release: record_indexed,
                media_allocation_release: record_media,
            };
        }
        guard
    }
    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            MEDIA_SLOT_RELEASE_OPS = MediaSlotReleaseOps {
                indexed_resource_release: firmware_indexed_resource_release,
                media_allocation_release: firmware_media_allocation_release,
            };
        }
        drop(guard);
    }

    #[test]
    fn releases_both_slot_allocations_and_clears_their_words() {
        let guard = install_recorder();
        let mut owner = [0xa5u8; 0xfa0];
        let slot = 3;
        let indexed = 0x1234_5678u32;
        let allocation = 0x8765_4321u32;
        unsafe {
            owner.as_mut_ptr().add(INDEXED_RESOURCE_OFFSET + slot * 4).cast::<u32>().write(indexed);
            owner.as_mut_ptr().add(MEDIA_ALLOCATION_OFFSET + slot * 4).cast::<u32>().write(allocation);
            media_slot_release(owner.as_mut_ptr(), slot as u32);
            assert_eq!(INDEXED_CALLS, 1);
            assert_eq!(INDEXED_CALL, (indexed as usize as *mut u8, 0, u32::MAX));
            assert_eq!(MEDIA_CALLS, 1);
            assert_eq!(MEDIA_CALL, allocation as usize as *mut u8);
            assert_eq!(owner.as_ptr().add(INDEXED_RESOURCE_OFFSET + slot * 4).cast::<u32>().read(), 0);
            assert_eq!(owner.as_ptr().add(MEDIA_ALLOCATION_OFFSET + slot * 4).cast::<u32>().read(), 0);
        }
        restore_default(guard);
    }

    #[test]
    fn skips_unsupported_slots_without_touching_fields() {
        let guard = install_recorder();
        let mut owner = [0u8; 0xfa0];
        unsafe {
            for slot in [2usize, 4] {
                owner.as_mut_ptr().add(INDEXED_RESOURCE_OFFSET + slot * 4).cast::<u32>().write(0x1111_0000 + slot as u32);
                owner.as_mut_ptr().add(MEDIA_ALLOCATION_OFFSET + slot * 4).cast::<u32>().write(0x2222_0000 + slot as u32);
                media_slot_release(owner.as_mut_ptr(), slot as u32);
                assert_eq!(owner.as_ptr().add(INDEXED_RESOURCE_OFFSET + slot * 4).cast::<u32>().read(), 0x1111_0000 + slot as u32);
                assert_eq!(owner.as_ptr().add(MEDIA_ALLOCATION_OFFSET + slot * 4).cast::<u32>().read(), 0x2222_0000 + slot as u32);
            }
            assert_eq!(INDEXED_CALLS, 0);
            assert_eq!(MEDIA_CALLS, 0);
        }
        restore_default(guard);
    }

    #[test]
    fn releases_each_nonzero_field_independently() {
        let guard = install_recorder();
        let mut owner = [0u8; 0xfa0];
        unsafe {
            owner.as_mut_ptr().add(INDEXED_RESOURCE_OFFSET).cast::<u32>().write(0x1111_2222);
            media_slot_release(owner.as_mut_ptr(), 0);
            assert_eq!(INDEXED_CALLS, 1);
            assert_eq!(MEDIA_CALLS, 0);
            owner.as_mut_ptr().add(MEDIA_ALLOCATION_OFFSET + 4).cast::<u32>().write(0x3333_4444);
            media_slot_release(owner.as_mut_ptr(), 1);
            assert_eq!(INDEXED_CALLS, 1);
            assert_eq!(MEDIA_CALLS, 1);
        }
        restore_default(guard);
    }
}
