//! `graphics_buffer_release` — `FUN_0824c798` @ **0x0824c798**.
//! True extent: **40 bytes**, 0x0824c798..0x0824c7bf; the next function
//! starts at 0x0824c7c0. Whole-image raw ARM decoding finds **2 incoming
//! plain BL calls** (0x0824ce9c, 0x08250020), **0 predicated BL calls**.
//! The body has one plain BL to the ported `free` @ 0x0802edc8.
//!
//! Algorithm: read the graphics buffer's owned data pointer at word 0. If
//! zero, leave the record unchanged. Otherwise free it, then clear the data
//! pointer and byte length at word 1, preserving the usage byte at +8.
//! No behavioral deviations. Target fields remain u32 words on hosts; a
//! private generic release operation permits isolated ordering tests without
//! replacing the shared heap table. Production uses the existing free port.

use crate::runtime::malloc_rt::free;

/// Releases the owned data of a graphics buffer record.
///
/// # Safety
/// `buffer` points to at least two aligned, writable target u32 words. Its
/// nonzero first word is an owned allocation accepted by `free`. The record
/// remains valid across that call. A NULL record is not accepted.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn graphics_buffer_release(buffer: *mut u32) {
    release_with(buffer, |data| free(data));
}

#[inline(always)]
unsafe fn release_with(buffer: *mut u32, release: impl FnOnce(*mut u8)) {
    let data = buffer.read();
    if data != 0 {
        release(data as usize as *mut u8);
        buffer.write(0);
        buffer.add(1).write(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_data_preserves_stale_length_and_usage() {
        let mut buffer = [0, 0xffff_ffff, 0xa5a5_5a5a];
        unsafe {
            release_with(buffer.as_mut_ptr(), |_| panic!("NULL data must not be freed"));
        }
        assert_eq!(buffer, [0, 0xffff_ffff, 0xa5a5_5a5a]);
    }

    #[test]
    fn releases_before_clearing_only_pointer_and_length_then_is_idempotent() {
        for length in [0, 1, 0x8000_0000, u32::MAX] {
            let mut buffer = [0x1234_5678, length, 0xa5a5_5a5a];
            let record = buffer.as_mut_ptr();
            let mut releases = 0;
            unsafe {
                release_with(record, |data| {
                    releases += 1;
                    assert_eq!(data as usize, 0x1234_5678);
                    assert_eq!(record.read(), 0x1234_5678);
                    assert_eq!(record.add(1).read(), length);
                });
                release_with(record, |_| panic!("released data must not be freed twice"));
            }
            assert_eq!(releases, 1);
            assert_eq!(buffer, [0, 0, 0xa5a5_5a5a]);
        }
    }
}
