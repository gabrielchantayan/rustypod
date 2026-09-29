//! SQLite pager checksum — `FUN_082dd844` @ 0x082dd844 (40 bytes; two
//! inbound plain `bl` call sites and no predicated `bl` call sites).
//!
//! Raw ARM spans 0x082dd844..0x082dd868; the next separately entered function
//! begins at 0x082dd86c with `push {r0,r1,r4-r11,lr}`. The function starts with
//! `Pager.cksumInit` at +0x34 and, while the signed result of subtracting 200
//! from `Pager.pageSize` at +0x40 remains positive, adds the byte at that
//! descending offset in page data. No deliberate deviations.

/// Computes SQLite's sparse pager checksum.
///
/// # Safety
///
/// `pager` must be a readable target-layout Pager. `page_data` must cover each
/// byte selected by its signed-positive descending 200-byte offsets.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pager_checksum(pager: *const u32, page_data: *const u8) -> u32 {
    let mut checksum = unsafe { pager.add(0x34 / 4).read() };
    let mut offset = unsafe { pager.add(0x40 / 4).read() };
    loop {
        offset = offset.wrapping_sub(200);
        if (offset as i32) <= 0 {
            return checksum;
        }
        checksum = checksum.wrapping_add(unsafe { page_data.add(offset as usize).read() } as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::pager_checksum;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const FIXTURE_LEN: usize = 0x1000;
    const DATA_OFFSET: usize = 0x200;

    fn reference(seed: u32, page_size: u32, data: &[u8]) -> u32 {
        let mut checksum = seed;
        let mut offset = page_size;
        loop {
            offset = offset.wrapping_sub(200);
            if (offset as i32) <= 0 {
                return checksum;
            }
            checksum = checksum.wrapping_add(data[offset as usize] as u32);
        }
    }

    #[test]
    fn samples_signed_positive_descending_offsets_and_wraps_the_seed() {
        let Some(base) = try_map_u32_slab(hints::SQLITE_PAGER_CHECKSUM, FIXTURE_LEN) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let page_sizes = [0, 1, 200, 201, 400, 401, 800];
        unsafe {
            let pager = base.cast::<u32>();
            let data = base.add(DATA_OFFSET);
            for index in 0..FIXTURE_LEN - DATA_OFFSET {
                data.add(index).write((index as u8).wrapping_mul(37).wrapping_add(11));
            }
            pager.add(0x34 / 4).write(u32::MAX - 5);
            for page_size in page_sizes {
                pager.add(0x40 / 4).write(page_size);
                assert_eq!(
                    pager_checksum(pager, data),
                    reference(u32::MAX - 5, page_size, core::slice::from_raw_parts(data, FIXTURE_LEN - DATA_OFFSET)),
                    "page size {page_size}",
                );
            }
        }
    }
}
