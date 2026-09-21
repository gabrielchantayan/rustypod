//! Inclusive signed range lookup used by the UI input tables.

/// Target-layout descriptor: the first and last accepted signed keys and a
/// 32-bit target pointer to the byte table. `data` remains `u32` even on host
/// builds because retailOS stores a four-byte ARM pointer at offset `+8`.
#[repr(C)]
pub struct RangeByteTable {
    pub first: i32,
    pub last: i32,
    pub data: u32,
}

/// `range_byte_lookup` — original: `FUN_0829f1f4` @ `0x0829f1f4` (32 bytes,
/// `0x0829f1f4..0x0829f213`; the next separately entered function starts at
/// `0x0829f214` with `mov r0,#0`). Raw words decode no internal plain or
/// predicated `bl` instructions. There are three inbound plain `bl` calls
/// (0x080dae2c, 0x082331ec, and 0x08233230); none is predicated.
///
/// Performs an inclusive signed range check of `key` against `table.first` and
/// `table.last`. On success, returns the byte at `table.data + key`; otherwise
/// returns zero. The signed checks and byte index intentionally allow negative
/// keys when the table's base pointer is arranged for them, exactly as the ARM
/// `ldrbge r0,[r0,r1]` does.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `table` must be readable for 12 bytes. When `key` is in range, `data + key`
/// must designate one readable byte in the target address space.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn range_byte_lookup(table: *const RangeByteTable, key: i32) -> u8 {
    let first = unsafe { (*table).first };
    if first > key {
        return 0;
    }

    let last = unsafe { (*table).last };
    if key > last {
        return 0;
    }

    let byte_address = (unsafe { (*table).data }).wrapping_add(key as u32) as usize;
    unsafe { (byte_address as *const u8).read() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn returns_bytes_only_for_the_inclusive_signed_range() {
        let Some(slab) = try_map_u32_slab(hints::RANGE_BYTE_LOOKUP, 0x1000) else {
            assert!(note_missing_u32_fixture("ui/range_byte_lookup"));
            return;
        };
        let data = unsafe { slab.add(0x100) };
        unsafe {
            data.sub(2).write(0x91);
            data.sub(1).write(0x92);
            data.write(0x93);
            data.add(1).write(0x94);
            data.add(2).write(0x95);
            (slab as *mut RangeByteTable).write(RangeByteTable {
                first: -2,
                last: 2,
                data: data as usize as u32,
            });
        }

        let table = slab as *const RangeByteTable;
        for (key, expected) in [
            (i32::MIN, 0),
            (-3, 0),
            (-2, 0x91),
            (-1, 0x92),
            (0, 0x93),
            (1, 0x94),
            (2, 0x95),
            (3, 0),
            (i32::MAX, 0),
        ] {
            assert_eq!(unsafe { range_byte_lookup(table, key) }, expected, "key={key}");
        }
    }
}
