//! `stream_write_owner_destroy` — original: `FUN_081f5478` @ 0x081f5478.
//!
//! # Extent and reachability, binary-verified
//!
//! Ghidra reports 56 bytes: raw `osos.dec` words confirm the fourteen-word
//! instruction body from 0x081f5478 through 0x081f54ac. The `ldr` at
//! 0x081f5480 reads the vtable literal at 0x081f54b0; 0x081f54b4 (`cmp r1,#0`)
//! starts the next independently entered function. Thus the code size is **56
//! bytes**, with a four-byte literal pool. Decoding every ARM B/BL immediate
//! finds three inbound plain `bl` calls (0x0812157c, 0x081215bc, 0x081f546c)
//! and zero predicated inbound `bl` calls. The body has no direct `bl`; its
//! only call is an unconditional indirect `blx` through vtable slot +4.
//!
//! # Algorithm
//!
//! Installs vtable 0x0899020c, then, if the target-width stream word at +8 is
//! nonzero, calls that object's vtable slot +4 with the stream as receiver,
//! clears the stream word, and returns the owner. The callback result is
//! discarded. Deliberate deviation: host tests store the vtable entries at
//! native pointer width while the target keeps 32-bit words; this preserves the
//! observed slot and callback ABI without assuming host pointers fit in `u32`.

use crate::cxx::stream_write_owner_construct::STREAM_WRITE_OWNER_VTABLE_ADDRESS;

type StreamRelease = unsafe extern "C" fn(*mut u8);

/// ARMv5TE vtable word index for byte offset +4.
const STREAM_RELEASE_VTABLE_INDEX: usize = 1;

/// Destroys the owned stream, if any, after restoring the owner vtable.
///
/// # Safety
///
/// `owner` must designate at least three writable target-width words. If its
/// third word is nonzero, it must be a valid target pointer to an object whose
/// first word is a vtable with a callable slot +4.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_write_owner_destroy")]
#[inline(never)]
pub unsafe extern "C" fn stream_write_owner_destroy(owner: *mut u32) -> *mut u32 {
    unsafe {
        owner.write_volatile(STREAM_WRITE_OWNER_VTABLE_ADDRESS);
        let stream = owner.add(2).read_volatile();
        if stream != 0 {
            #[cfg(target_os = "none")]
            let vtable = (stream as usize as *const *const StreamRelease).read_volatile();
            #[cfg(not(target_os = "none"))]
            let vtable = (stream as usize as *const u32).read_volatile() as usize as *const StreamRelease;
            let release = vtable.add(STREAM_RELEASE_VTABLE_INDEX).read_volatile();
            release(stream as usize as *mut u8);
            owner.add(2).write_volatile(0);
        }
    }
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_RECEIVER: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn release(stream: *mut u8) {
        RELEASE_CALLS.fetch_add(1, Ordering::SeqCst);
        RELEASE_RECEIVER.store(stream as usize, Ordering::SeqCst);
    }

    #[test]
    fn restores_vtable_releases_stream_and_clears_ownership() {
        let Some(slab) = try_map_u32_slab(hints::STREAM_WRITE_OWNER_DESTROY, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/stream_write_owner_destroy"));
            return;
        };
        let object = slab.cast::<u32>();
        let vtable = unsafe { slab.add(0x100).cast::<usize>() };
        unsafe {
            object.write(vtable as usize as u32);
            vtable.write(0);
            vtable.add(STREAM_RELEASE_VTABLE_INDEX).write(release as usize);
        }
        let mut owner = [0xdead_beef, 0x1111_2222, slab as usize as u32];
        RELEASE_CALLS.store(0, Ordering::SeqCst);
        RELEASE_RECEIVER.store(0, Ordering::SeqCst);

        let returned = unsafe { stream_write_owner_destroy(owner.as_mut_ptr()) };

        assert_eq!(returned, owner.as_mut_ptr());
        assert_eq!(owner[0], STREAM_WRITE_OWNER_VTABLE_ADDRESS);
        assert_eq!(owner[1], 0x1111_2222);
        assert_eq!(owner[2], 0);
        assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASE_RECEIVER.load(Ordering::SeqCst), slab as usize);
    }

    #[test]
    fn clears_null_stream_without_dispatch() {
        let mut owner = [0xdead_beef, 0x1111_2222, 0];
        RELEASE_CALLS.store(0, Ordering::SeqCst);

        let returned = unsafe { stream_write_owner_destroy(owner.as_mut_ptr()) };

        assert_eq!(returned, owner.as_mut_ptr());
        assert_eq!(owner, [STREAM_WRITE_OWNER_VTABLE_ADDRESS, 0x1111_2222, 0]);
        assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 0);
    }
}
