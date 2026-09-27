//! `scaled_byte_pair_hash_table_record_construct` — retailOS
//! `FUN_083d2148` at load address `0x083d2148` (92 bytes).
//!
//! Raw `osos.dec` establishes the exact 23-word A32 extent from `push
//! {r4,r5,r6,r7,r8,lr}` at `0x083d2148` through `pop {r4,r5,r6,r7,r8,pc}` at
//! `0x083d21a0`; `0x083d21a4` begins the next independently entered function.
//! The body has four unconditional plain `bl` instructions (`byte_pair_prefix_init`,
//! the unported sorted-table lookup at `0x0826f3bc`,
//! `hash_table_bucket_construct_083d3084`, and
//! `scaled_f32_count_ceiling_to_u32_083d24cc`) and no predicated direct calls.
//! Whole-image ARM direct-call decoding finds two inbound plain `bl` sites
//! (`0x08268ebc`, `0x0826a5e4`) and no predicated sites.
//!
//! It initializes the duplicated-byte prefix, fixes the scale to `1.0f`, looks
//! up the hash-table bucket count from `key`, clears the bucket-table cursor
//! fields, constructs the embedded bucket table at `this + 0x10`, then derives
//! the scaled count at `this + 0x0c`. It returns `this` unchanged.
//!
//! # Deliberate deviations
//!
//! The sorted-table helper at `0x0826f3bc` remains unported, so the target
//! invokes that exact address and host tests install a recording seam. Rust
//! uses byte offsets and volatile word stores to preserve the target's 32-bit
//! layout and observable store order on wider hosts.

use crate::cxx::byte_pair_prefix_init::byte_pair_prefix_init;
use crate::cxx::scaled_byte_pair_record_construct::TABLE_LOOKUP_ADDRESS;
use crate::fp::fp_scaled_count_ceiling_083d24cc::scaled_f32_count_ceiling_to_u32_083d24cc;
use crate::util::hash_table_bucket_construct::HashTableBuckets;
use crate::util::hash_table_bucket_construct_083d3084::hash_table_bucket_construct_083d3084;

/// The unported sorted-table lookup used to obtain the embedded table's count.
pub struct ScaledBytePairHashTableRecordOps {
    pub table_lookup: unsafe extern "C" fn(key: u32) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_table_lookup(key: u32) -> u32 {
    let lookup: unsafe extern "C" fn(u32) -> u32 = unsafe { core::mem::transmute(TABLE_LOOKUP_ADDRESS) };
    unsafe { lookup(key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_table_lookup(_key: u32) -> u32 {
    panic!("scaled_byte_pair_hash_table_record_construct requires table lookup 0x0826f3bc")
}

pub const DEFAULT_SCALED_BYTE_PAIR_HASH_TABLE_RECORD_OPS: ScaledBytePairHashTableRecordOps =
    ScaledBytePairHashTableRecordOps {
        #[cfg(target_os = "none")]
        table_lookup: firmware_table_lookup,
        #[cfg(not(target_os = "none"))]
        table_lookup: missing_table_lookup,
    };

pub static mut SCALED_BYTE_PAIR_HASH_TABLE_RECORD_OPS: ScaledBytePairHashTableRecordOps =
    DEFAULT_SCALED_BYTE_PAIR_HASH_TABLE_RECORD_OPS;

/// Constructs the 0x24-byte record at `this` and returns it unchanged.
///
/// # Safety
///
/// `this` must be four-byte aligned and writable for 0x24 bytes; `a` and `b`
/// must each be readable for one byte. The installed lookup and allocator
/// seams must be callable. The retail function has no null or alignment guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.scaled_byte_pair_hash_table_record_construct"))]
#[inline(never)]
pub unsafe extern "C" fn scaled_byte_pair_hash_table_record_construct(
    this: *mut u8,
    key: u32,
    a: *const u8,
    b: *const u8,
) -> *mut u8 {
    let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCALED_BYTE_PAIR_HASH_TABLE_RECORD_OPS)) };
    unsafe {
        byte_pair_prefix_init(this, a, b);
        this.add(0x08).cast::<u32>().write_volatile(0x3f80_0000);
        this.add(0x14).cast::<u32>().write_volatile(0);
        let bucket_count = (ops.table_lookup)(key);
        this.add(0x18).cast::<u32>().write_volatile(bucket_count);
        this.add(0x1c).cast::<u32>().write_volatile(0);
        this.add(0x20).cast::<u32>().write_volatile(0);
        hash_table_bucket_construct_083d3084(this.add(0x10).cast::<HashTableBuckets>());
        scaled_f32_count_ceiling_to_u32_083d24cc(this.cast::<u32>());
    }
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static mut LOOKUP_KEY: u32 = 0;
    static mut LOOKUP_RESULT: u32 = 0;

    unsafe extern "C" fn recording_table_lookup(key: u32) -> u32 {
        unsafe {
            LOOKUP_KEY = key;
            LOOKUP_RESULT
        }
    }

    fn install_lookup(result: u32) {
        unsafe {
            LOOKUP_KEY = 0;
            LOOKUP_RESULT = result;
            SCALED_BYTE_PAIR_HASH_TABLE_RECORD_OPS = ScaledBytePairHashTableRecordOps {
                table_lookup: recording_table_lookup,
            };
        }
    }

    fn reset_lookup() {
        unsafe {
            SCALED_BYTE_PAIR_HASH_TABLE_RECORD_OPS = DEFAULT_SCALED_BYTE_PAIR_HASH_TABLE_RECORD_OPS;
        }
    }

    #[test]
    fn constructs_prefix_scaled_count_and_embedded_bucket_table() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _heap = mock_heap();
        let Some(slab) = try_map_u32_slab(hints::SCALED_BYTE_PAIR_HASH_TABLE_RECORD_CONSTRUCT, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        install_lookup(2);

        unsafe {
            let this = slab.cast::<u8>();
            let buckets = slab.add(0x100).cast::<u32>();
            set_alloc_ret(buckets.cast());
            core::ptr::write_bytes(this, 0xa5, 0x24);
            let a: u32 = 0xdead_beef;
            let b: u32 = 0x1234_5678;

            let returned = scaled_byte_pair_hash_table_record_construct(
                this,
                0x32,
                (&a as *const u32).cast(),
                (&b as *const u32).cast(),
            );

            assert_eq!(returned, this);
            assert_eq!(&core::slice::from_raw_parts(this, 4), &[0xef, 0x78, 0xef, 0x78]);
            assert_eq!(this.add(4).cast::<u32>().read(), 0);
            assert_eq!(this.add(8).cast::<u32>().read(), 0x3f80_0000);
            assert_eq!(this.add(12).cast::<u32>().read(), 2);
            assert_eq!(LOOKUP_KEY, 0x32);
            assert_eq!(alloc_log().1, 12);
            assert_eq!(this.add(0x14).cast::<u32>().read(), buckets as usize as u32);
            assert_eq!(this.add(0x18).cast::<u32>().read(), 2);
            assert_eq!(this.add(0x1c).cast::<u32>().read(), buckets.add(2) as usize as u32);
            assert_eq!(this.add(0x20).cast::<u32>().read(), 0);
            assert_eq!([buckets.read(), buckets.add(1).read()], [0, 0]);
            assert_eq!(buckets.add(2).read(), buckets.add(2) as usize as u32);
        }
        reset_lookup();
    }
}
