//! `hash_table_bucket_slot` — original: `FUN_083d6e70` @ **0x083d6e70**
//! (**32 bytes**, exactly `0x083d6e70..0x083d6e90`; the next independent
//! leaf begins `ldr r0, [r0, #0x14]` @ `0x083d6e90`).
//!
//! Decoding all aligned ARM B/BL immediates in `osos.dec` finds **3 direct,
//! unconditional inbound `bl` call sites** — `0x083d2da0`, `0x083d2eac`, and
//! `0x083d2fdc` — and no predicated inbound calls. The body has one plain
//! `bl` to `__rt_udiv` @ `0x08036f14`, with no predicated calls.
//!
//! Algorithm: divide `hash` by the table's bucket count at `table + 8`; the
//! ADS helper leaves the remainder in r1. Return the address of bucket
//! `remainder` in the u32 bucket array whose base is at `table + 4`.
//!
//! ## Deliberate deviations
//!
//! Rust's ABI cannot consume the ADS helper's r1 remainder, so this calls the
//! existing `__rt_udivmod` wrapper with a stack out-pointer. It preserves the
//! observable quotient/remainder semantics and the out-of-line divide seam.

use core::ptr;

use crate::runtime::rt_div::__rt_udivmod;

/// `hash_table_bucket_slot` — original `FUN_083d6e70` @ `0x083d6e70`.
///
/// Returns `table.bucket_base[hash % table.bucket_count]`. `table` must point
/// to an aligned target-layout object with u32 bucket base and count words at
/// offsets `+4` and `+8`; the bucket array must contain `bucket_count` u32s.
/// Neither pointer nor a zero count is checked, matching the retail routine.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_bucket_slot(table: *const u8, hash: u32) -> *mut u32 {
    let bucket_base = ptr::read(table.add(4) as *const u32);
    let bucket_count = ptr::read(table.add(8) as *const u32);
    let mut remainder = 0;
    __rt_udivmod(hash, bucket_count, &mut remainder);
    (bucket_base as *mut u32).add(remainder as usize)
}

/// `hash_table_bucket_slot_6e50` — original `FUN_083d6e50` @ `0x083d6e50`.
///
/// Raw osos.dec words `e92d4010 e1a04000 e1a00001 e5941008 ebf1802b
/// e5940004 e0800101 e8bd8010` establish the 32-byte extent through
/// `0x083d6e70`. Aligned ARM decoding finds three inbound plain `bl` sites
/// (`0x083d2a78`, `0x083d2b84`, `0x083d2cbc`) and no predicated inbound calls;
/// its body makes one plain call to `__rt_udiv` and no predicated calls.
///
/// It returns `table.bucket_base[hash % table.bucket_count]`; this separate
/// export retains the assigned BL target. Its target-only text section prevents
/// LLVM from folding this required hook entry into the identical 0x083d6e70
/// body. As above, `__rt_udivmod` deliberately exposes ADS's r1 remainder
/// through an out-pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.hash_table_bucket_slot_6e50")]
#[inline(never)]
pub unsafe extern "C" fn hash_table_bucket_slot_6e50(table: *const u8, hash: u32) -> *mut u32 {
    let bucket_base = ptr::read(table.add(4) as *const u32);
    let bucket_count = ptr::read(table.add(8) as *const u32);
    let mut remainder = 0;
    __rt_udivmod(hash, bucket_count, &mut remainder);
    (bucket_base as *mut u32).add(remainder as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const BUCKET_OFFSET: usize = 0x100;
    const BUCKET_COUNT: u32 = 7;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::HASH_TABLE_BUCKET_SLOT, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    #[test]
    fn bucket_slot_uses_unsigned_remainder_and_target_word_layout() {
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/hash_table_bucket_slot"));
            return;
        };
        let table = slab as *mut u8;
        let buckets = unsafe { table.add(BUCKET_OFFSET) as *mut u32 };
        unsafe {
            ptr::write_bytes(table, 0, FIXTURE_LEN);
            ptr::write(table.add(4) as *mut u32, buckets as usize as u32);
            ptr::write(table.add(8) as *mut u32, BUCKET_COUNT);

            for hash in [0, 1, BUCKET_COUNT - 1, BUCKET_COUNT, u32::MAX] {
                let slot = hash_table_bucket_slot(table, hash);
                assert_eq!(slot, buckets.add((hash % BUCKET_COUNT) as usize));
                let target_slot = hash_table_bucket_slot_6e50(table, hash);
                assert_eq!(target_slot, buckets.add((hash % BUCKET_COUNT) as usize));
            }

            ptr::write(table.add(8) as *mut u32, 1);
            assert_eq!(hash_table_bucket_slot(table, u32::MAX), buckets);
        }
    }
}
