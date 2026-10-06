use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// Acquire the current audio buffer — `FUN_08167e7c` @ 0x08167e7c.
/// True extent: 116 bytes, [0x08167e7c, 0x08167ef0).
/// Verified calls: three outbound plain BLs, zero predicated BLs;
/// two inbound plain BLs, zero predicated BLs.
/// Lock ring+0x14, clear the output, and accept the current record only
/// if its length is 0x80000 or draining is nonzero. Copy its address,
/// unlock, then reload the read index and length for the return value.
/// The second argument is unused. No buffer is removed or index advanced.
/// Deviations: volatile aligned word accesses preserve stock ordering and
/// aliasing; native Mutex layout is used on hosts, as in the release port.
///
/// # Safety
/// `ring` must be word-aligned and contain a valid native-layout Mutex at
/// +0x14, the read index at +0x334, and every selected 12-byte record.
/// `buffer_address` must be writable and word-aligned; it may alias ring
/// words provided all resulting indices select valid records. Stored buffer
/// addresses remain target u32 words, not native host pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn audio_buffer_ring_acquire(
    ring: *mut u32,
    _requested_length: u32,
    buffer_address: *mut u32,
    draining: u32,
) -> u32 {
    let mutex = ring.add(5).cast::<Mutex>();
    mutex_lock(mutex);
    buffer_address.write_volatile(0);
    let index = ring.add(0x334 / 4);
    let offset = index.read_volatile().wrapping_mul(12);
    let length = ring.cast::<u8>().wrapping_add(offset.wrapping_add(0x38) as usize)
        .cast::<u32>().read_volatile();
    if length != 0x80000 && draining == 0 {
        mutex_unlock(mutex);
        return 0;
    }
    let address = ring.cast::<u8>().wrapping_add(offset.wrapping_add(0x30) as usize)
        .cast::<u32>().read_volatile();
    buffer_address.write_volatile(address);
    mutex_unlock(mutex);
    let offset = index.read_volatile().wrapping_mul(12).wrapping_add(0x38);
    ring.cast::<u8>().wrapping_add(offset as usize).cast::<u32>().read_volatile()
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn fixture(storage: &mut [u64; 106]) -> *mut u32 {
        // Base +4 aligns the native Mutex at target offset +0x14.
        let ring = storage.as_mut_ptr().cast::<u32>().add(1);
        ring.add(5).cast::<Mutex>().write(Mutex {
            sem_cell: core::ptr::null_mut(), unused: 0,
        });
        ring
    }

    #[test]
    fn full_only_unless_draining_and_never_consumes_record() {
        for index in [0u32, 1, 63, u32::MAX] {
            for length in [0, 1, 0x7ffff, 0x80000, 0x80001, u32::MAX] {
                for draining in [0, 1, u32::MAX] {
                    let mut storage = [0u64; 106];
                    unsafe {
                        let ring = fixture(&mut storage);
                        ring.add(0x334 / 4).write(index);
                        let offset = index.wrapping_mul(12);
                        ring.cast::<u8>().wrapping_add(offset.wrapping_add(0x30) as usize)
                            .cast::<u32>().write(0xdeadbeef);
                        ring.cast::<u8>().wrapping_add(offset.wrapping_add(0x38) as usize)
                            .cast::<u32>().write(length);
                        let before = storage;
                        let mut output = 0x12345678;
                        let accepted = length == 0x80000 || draining != 0;
                        // r1 does not change the fixed full-buffer threshold.
                        let result = audio_buffer_ring_acquire(ring, 1, &mut output, draining);
                        assert_eq!(result, if accepted { length } else { 0 });
                        assert_eq!(output, if accepted { 0xdeadbeef } else { 0 });
                        assert_eq!(storage, before);
                    }
                }
            }
        }
    }

    #[test]
    fn output_aliases_preserve_clear_and_return_reload_order() {
        let mut storage = [0u64; 106];
        unsafe {
            let ring = fixture(&mut storage);
            ring.add(0x30 / 4).write(1);
            ring.add(0x38 / 4).write(0x80000);
            ring.add((0x38 + 12) / 4).write(17);
            // Copying the buffer word changes the index before the return read.
            assert_eq!(audio_buffer_ring_acquire(ring, 0, ring.add(0x334 / 4), 0), 17);
            assert_eq!(ring.add(0x334 / 4).read(), 1);
            ring.add(0x334 / 4).write(0);
            // Clearing output precedes even the initial length check.
            assert_eq!(audio_buffer_ring_acquire(ring, 0x80000, ring.add(0x38 / 4), 0), 0);
            assert_eq!(ring.add(0x38 / 4).read(), 0);
            ring.add(0x38 / 4).write(9);
            // Draining accepts zero length too; copy overwrites the length.
            assert_eq!(audio_buffer_ring_acquire(ring, 0, ring.add(0x38 / 4), 1), 1);
        }
    }
}
