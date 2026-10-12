//! NUL-terminated string lookup for a liti entry.

use super::liti_field_class_check::liti_field_class_check;
use crate::util::string_pool::{string_pool_read, StringPool, PARAM_ERR};

/// `liti_entry_read_string` — `FUN_0805235c` @ `0x0805235c`, 96 bytes.
///
/// Raw ARM spans 0x0805235c..0x080523bc, ending in pop {r2-r6,pc};
/// the next function starts with push {r2-r10,lr}. Whole-image A32 decoding
/// finds two incoming plain BLs (0x08107074, 0x0813e784), no predicated
/// incoming BLs. The body has two plain BLs and no predicated BLs, calling
/// the liti field predicate and string-pool reader respectively.
///
/// Reject invalid class, NULL destination, or zero capacity with -50 without
/// modifying the destination. Otherwise clear its first byte, read the ID at
/// entry+0x20 from the pool at *(entry+4)+0x34 with capacity-1, and append
/// NUL at the returned byte length only on success. Propagate reader errors.
///
/// Deliberate deviations: direct calls to existing Rust ports. The apparent
/// fourth Ghidra argument is not an input: its saved stack word is overwritten
/// with zero before the reader call. Target pointers remain aligned u32 words
/// on hosts; the inline StringPool uses its canonical native-pointer layout.
///
/// # Safety
/// Non-NULL entry must satisfy liti_field_class_check and, if accepted with
/// nonzero capacity and destination, be readable through +0x20. Its word-one
/// pointer must contain a StringPool at +0x34. Destination must accommodate
/// the reader's signed-clamped copy plus NUL; as in retailOS, capacities with
/// a negative signed capacity-1 are not guarded.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn liti_entry_read_string(
    entry: *const u8,
    dst: *mut u8,
    capacity: u32,
) -> i32 {
    if liti_field_class_check(entry) == 0 || dst.is_null() || capacity == 0 {
        return PARAM_ERR;
    }
    dst.write(0);
    let words = entry.cast::<u32>();
    let library = words.add(1).read() as usize as *mut u8;
    let id = words.add(8).read() as i32;
    let mut length = 0;
    let status = string_pool_read(
        library.add(0x34).cast::<StringPool>(), id, dst, &mut length,
        capacity.wrapping_sub(1),
    );
    if status == 0 {
        dst.add(length as usize).write(0);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_truncates_terminates_and_preserves_rejected_buffers() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::LITI_ENTRY_READ_STRING, 4096,
        ).expect("target-width library fixture");
        unsafe {
            // +0x34 must be naturally aligned for host StringPool pointers.
            let library = slab.add(4);
            library.cast::<u32>().write(0x6974_696c);
            let pool = library.add(0x34).cast::<StringPool>();
            pool.write(core::mem::zeroed());
            (*pool).tag = 0x7374_7263;
            (*pool).entry_count = 1;
            let mut payload = *b"hello";
            let mut payload_ptr = payload.as_mut_ptr();
            let mut record = crate::util::string_pool::PoolEntry {
                blob_offset: 0, length: 5,
            };
            let mut record_ptr = &mut record as *mut _;
            (*pool).entries = &mut record_ptr;
            (*pool).payload = &mut payload_ptr;
            let mut entry = [0u32; 9];
            entry[1] = library as usize as u32;
            entry[8] = 1;
            for (capacity, expected) in [(1, &b"\0"[..]), (4, &b"hel\0"[..]), (6, &b"hello\0"[..]), (8, &b"hello\0"[..])] {
                let mut dst = [0xa5; 10];
                assert_eq!(liti_entry_read_string(entry.as_ptr().cast(), dst.as_mut_ptr(), capacity), 0);
                assert_eq!(&dst[..expected.len()], expected);
                assert!(dst[expected.len()..].iter().all(|&byte| byte == 0xa5));
            }
            let mut dst = [0xa5; 10];
            assert_eq!(liti_entry_read_string(entry.as_ptr().cast(), dst.as_mut_ptr(), 0), PARAM_ERR);
            assert_eq!(dst, [0xa5; 10]);
            assert_eq!(liti_entry_read_string(entry.as_ptr().cast(), core::ptr::null_mut(), 6), PARAM_ERR);
            library.cast::<u32>().write(0);
            assert_eq!(liti_entry_read_string(entry.as_ptr().cast(), dst.as_mut_ptr(), 6), PARAM_ERR);
            assert_eq!(dst, [0xa5; 10]);
            library.cast::<u32>().write(0x6974_696c);
            for id in [u32::MAX, 2] {
                entry[8] = id;
                dst.fill(0xa5);
                assert_eq!(liti_entry_read_string(entry.as_ptr().cast(), dst.as_mut_ptr(), 6), PARAM_ERR);
                assert_eq!(dst[0], 0);
                assert_eq!(&dst[1..], &[0xa5; 9]);
            }
            entry[8] = 0;
            dst.fill(0xa5);
            assert_eq!(liti_entry_read_string(entry.as_ptr().cast(), dst.as_mut_ptr(), 6), 0);
            assert_eq!(dst[0], 0);
            assert_eq!(&dst[1..], &[0xa5; 9]);
            assert_eq!(liti_entry_read_string(core::ptr::null(), dst.as_mut_ptr(), 6), PARAM_ERR);
        }
    }
}
