//! Filtered primary-record lookup: `FUN_080ffdf0` @ `0x080ffdf0`.
//!
//! 116 instruction bytes (0x080ffdf0..0x080ffe64), followed by the table
//! literal at 0x080ffe64; next real function starts at 0x080ffe68 (120-byte
//! extent including literal). Two plain inbound BLs at 0x080ffcb0/0x080ffcd4,
//! no predicated inbound BLs; body has two plain BLs, no predicated BLs.
//! Scan all 205 twenty-byte records at 0x083e9d94 in order. Compare the full
//! category argument to +8, resolve the +16 secondary key to a signed value,
//! then compare the opaque runtime query on the +10 ID to (requested != 0).
//! Return the first matching ID, or zero. No target behavior deviations.
//! The unnamed 0x080ffea0 callee remains a direct retail-address operation;
//! host verification injects the table and operations into the same scan.
#[cfg(test)]
extern crate std;


#[repr(C)]
#[derive(Clone, Copy)]
struct PrimaryRecord {
    prefix: [u16; 4],
    category: u16,
    id: u16,
    middle: [u16; 2],
    secondary_key: u16,
    suffix: u16,
}

const RECORD_COUNT: usize = 205;
const _: [u8; 20] = [0; core::mem::size_of::<PrimaryRecord>()];
const _: [u8; 8] = [0; core::mem::offset_of!(PrimaryRecord, category)];
const _: [u8; 10] = [0; core::mem::offset_of!(PrimaryRecord, id)];
const _: [u8; 16] = [0; core::mem::offset_of!(PrimaryRecord, secondary_key)];

#[inline(always)]
unsafe fn lookup(
    table: *const PrimaryRecord, value: i32, requested: i32, category: u32,
    mut resolve: impl FnMut(u32) -> i32, mut query: impl FnMut(u32) -> u32,
) -> u32 {
    for index in 0..RECORD_COUNT {
        let record = table.add(index);
        if u32::from(core::ptr::addr_of!((*record).category).read()) != category {
            continue;
        }
        if resolve(u32::from(core::ptr::addr_of!((*record).secondary_key).read())) != value {
            continue;
        }
        let id = u32::from(core::ptr::addr_of!((*record).id).read());
        if query(id) == u32::from(requested != 0) {
            // Reload after the runtime operation, as the original does.
            return u32::from(core::ptr::addr_of!((*record).id).read());
        }
    }
    0
}

/// Return the first primary-record ID matching all three filters.
///
/// # Safety
/// Requires the stock table layout and executable retail code at 0x080ffea0.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn primary_record_id_lookup(value: i32, requested: i32, category: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let query: unsafe extern "C" fn(u32) -> u32 = core::mem::transmute(0x080f_fea0usize);
        lookup(0x083e_9d94usize as *const PrimaryRecord, value, requested, category,
            |key| super::secondary_record_value_lookup::secondary_record_value_lookup(key),
            |id| query(id))
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (value, requested, category);
        panic!("primary_record_id_lookup requires retail firmware; host tests inject operations")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const EMPTY: PrimaryRecord = PrimaryRecord {
        prefix: [0; 4], category: 0, id: 0, middle: [0; 2], secondary_key: 0, suffix: 0,
    };

    #[test]
    fn filters_in_order_and_returns_first_match() {
        let mut table = [EMPTY; RECORD_COUNT];
        for (i, key) in [10, 11, 12, 13].into_iter().enumerate() {
            table[i] = PrimaryRecord { category: 7, id: 100 + i as u16, secondary_key: key, ..EMPTY };
        }
        table[0].category = 6;
        let mut resolved = std::vec::Vec::new();
        let mut queried = std::vec::Vec::new();
        let result = unsafe { lookup(table.as_ptr(), -12, -1, 7,
            |key| { resolved.push(key); if key == 11 { 12 } else { -12 } },
            |id| { queried.push(id); if id == 102 { 0 } else { 1 } }) };
        assert_eq!(result, 103);
        assert_eq!(resolved, [11, 12, 13]);
        assert_eq!(queried, [102, 103]);
    }

    #[test]
    fn last_record_full_width_category_and_exact_query_result() {
        let mut table = [EMPTY; RECORD_COUNT];
        table[204] = PrimaryRecord { category: 0xffff, id: 0xffff, secondary_key: 55, ..EMPTY };
        for requested in [1, -1, i32::MIN] {
            assert_eq!(unsafe { lookup(table.as_ptr(), i32::MAX, requested, 0xffff,
                |_| i32::MAX, |_| 1) }, 0xffff);
        }
        assert_eq!(unsafe { lookup(table.as_ptr(), -32768, 0, 0xffff, |_| -32768, |_| 0) }, 0xffff);
        assert_eq!(unsafe { lookup(table.as_ptr(), 0, 1, 0xffff, |_| 0, |_| 2) }, 0);
        assert_eq!(unsafe { lookup(table.as_ptr(), 0, 0, 0x1ffff,
            |_| panic!("category must not truncate"), |_| panic!("no query")) }, 0);
        assert_eq!(unsafe { lookup(table.as_ptr(), 0, 0, 123,
            |_| panic!("no matching category"), |_| panic!("no query")) }, 0);
    }

    #[test]
    fn matching_zero_id_terminates_search() {
        let mut table = [EMPTY; RECORD_COUNT];
        table[1].id = 99;
        let mut calls = 0;
        assert_eq!(unsafe { lookup(table.as_ptr(), 0, 0, 0, |_| 0,
            |_| { calls += 1; 0 }) }, 0);
        assert_eq!(calls, 1);
    }
}
