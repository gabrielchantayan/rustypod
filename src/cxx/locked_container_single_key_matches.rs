//! Locked singleton-key predicate — `FUN_081e201c` @ **0x081e201c**.
//!
//! True extent: **92 bytes**, ending at 0x081e2078, the next function's
//! push {r3,r4,r5,r6,r7,lr}. Raw A32 words contain four outgoing plain BLs
//! and zero predicated BLs. Whole-image decoding finds two incoming plain
//! BLs (0x082971dc, 0x08297274), zero predicated BLs.
//!
//! Acquire the counted lock pointed to by header+0x1c. Only when the count
//! at +0x14 equals one, resolve the first node through the existing accessor
//! and compare its key at +0x10. Release the lock on every return path.
//! Deliberate deviations: omit dead stack homes and share the release path;
//! use target-width words for opaque firmware pointers on every host.

use crate::cxx::container_first_node_083dbde8::cxx_container_first_node_083dbde8;
use crate::kernel::sync_mutex::{counted_mutex_guard_acquire_lock, mutex_unlock_counted, CountedMutex};

/// # Safety
/// `header` must be word-aligned and readable through +0x1c, with a valid
/// counted-lock pointer there. If count is one, its nested container and
/// first node must be valid, with the node readable through +0x10.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn locked_container_single_key_matches(header: *const u32, key: u32) -> u32 {
    let lock = header.add(7).read() as usize as *mut CountedMutex;
    let mut guard = core::ptr::null_mut();
    counted_mutex_guard_acquire_lock(&mut guard, lock);
    let matches = if header.add(5).read() == 1 {
        let node = cxx_container_first_node_083dbde8(header.cast());
        node.add(0x10).cast::<u32>().read() == key
    } else {
        false
    };
    mutex_unlock_counted(guard);
    matches as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::sync_mutex::Mutex;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn singleton_key_and_short_circuit_preserve_lock_and_container() {
        let Some(slab) = try_map_u32_slab(hints::LOCKED_CONTAINER_SINGLE_KEY_MATCHES, 0x1000) else {
            return;
        };
        unsafe {
            let header = slab.add(0x100).cast::<u32>();
            let nested = slab.add(0x200).cast::<u32>();
            let node = slab.add(0x300).cast::<u32>();
            let lock = slab.add(0x400).cast::<CountedMutex>();
            lock.write(CountedMutex {
                mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
                hold_count: 0,
            });
            header.add(7).write(lock as usize as u32);
            // Non-singletons must not dereference the deliberately null nested pointer.
            header.add(4).write(0);
            for count in [0, 2, u32::MAX] {
                header.add(5).write(count);
                assert_eq!(locked_container_single_key_matches(header, 0), 0);
                assert_eq!((*lock).hold_count, 0);
                assert_eq!(header.add(5).read(), count);
            }
            header.add(4).write(nested as usize as u32);
            nested.add(2).write(node as usize as u32);
            header.add(5).write(1);
            node.add(3).write(0x12345678); // Adjacent word is not the key.
            for stored in [0, 0x80000000, u32::MAX] {
                node.add(4).write(stored);
                for requested in [stored, stored.wrapping_add(1)] {
                    assert_eq!(locked_container_single_key_matches(header, requested),
                        (stored == requested) as u32);
                    assert_eq!((*lock).hold_count, 0);
                    assert_eq!(node.add(4).read(), stored);
                    assert_eq!(header.add(5).read(), 1);
                }
            }
        }
    }
}
