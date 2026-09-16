//! `byte_key_word_map_lookup_or_insert` — original: `FUN_083db0d0` @
//! **0x083db0d0** (**60 bytes**, exactly `0x083db0d0..0x083db10b`; the
//! next function opens `push {r4-r6,lr}` @ `0x083db10c`).
//!
//! Raw ARM B/BL decoding finds four inbound direct calls, all unconditional
//! plain `bl`; none is predicated. The body contains one plain `bl`, to the
//! still-retail byte-key tree insert-unique operation @ `0x083b9bac`.
//!
//! It reads `*key`, builds the target-width `{u8 key, three padding bytes,
//! u32 value=0}` pair on its stack, calls the tree operation, and returns
//! `node + 0x14`: the mapped-word slot. This is the ADS
//! `std::map<u8, u32>::operator[]` shape.
//!
//! Deliberate deviations: the retail tree operation is a direct load-address
//! call on device but uses a host recording seam; the three padding bytes,
//! uninitialized in the original, are zeroed. The original's dead store of
//! the returned node into its dying stack frame is omitted.

use core::ptr::{addr_of, addr_of_mut};

/// Firmware load address of the still-retail byte-key tree insert-unique
/// operation `FUN_083b9bac`.
pub const BYTE_KEY_WORD_TREE_INSERT_UNIQUE_ADDRESS: usize = 0x083b_9bac;

/// ABI of the tree operation. `out[0]` receives a target pointer to the node;
/// it may write its inserted flag byte at `out + 4`. `pair` is `{key, 0}`.
pub type ByteKeyWordTreeInsertUnique = unsafe extern "C" fn(
    out: *mut u32,
    map: *mut u8,
    pair: *const u32,
);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_byte_key_word_tree_insert_unique(
    out: *mut u32,
    map: *mut u8,
    pair: *const u32,
) {
    let insert: ByteKeyWordTreeInsertUnique =
        core::mem::transmute(BYTE_KEY_WORD_TREE_INSERT_UNIQUE_ADDRESS);
    insert(out, map, pair);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_byte_key_word_tree_insert_unique(
    _out: *mut u32,
    _map: *mut u8,
    _pair: *const u32,
) {
    panic!("byte_key_word_map_lookup_or_insert requires tree operation 0x083b9bac")
}

/// Boundary for the still-retail tree operation. Device builds call its fixed
/// load address; host tests replace this seam to inspect the target ABI.
#[cfg(target_os = "none")]
pub static mut BYTE_KEY_WORD_TREE_INSERT_UNIQUE: ByteKeyWordTreeInsertUnique =
    firmware_byte_key_word_tree_insert_unique;

#[cfg(not(target_os = "none"))]
pub static mut BYTE_KEY_WORD_TREE_INSERT_UNIQUE: ByteKeyWordTreeInsertUnique =
    missing_byte_key_word_tree_insert_unique;

/// byte_key_word_map_lookup_or_insert — original: `FUN_083db0d0` @
/// `0x083db0d0` (60 bytes; 4 direct unconditional `bl` call sites; one plain
/// `bl` in the body and no predicated calls).
///
/// Finds or inserts `*key` in `map`, default-initializing a new mapped word,
/// then returns that word's address (`node + 0x14`).
///
/// # Safety
/// `key` must point to a readable byte; `map` must be the retail map object
/// expected by the installed tree operation. As in retailOS, neither pointer
/// is NULL-checked and callers may dereference the returned slot immediately.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_key_word_map_lookup_or_insert(
    map: *mut u8,
    key: *const u8,
) -> *mut u32 {
    let pair = [key.read() as u32, 0];
    // Target-equivalent 12-byte result frame: node word plus space for the
    // inserted flag byte at +4, which this wrapper intentionally ignores.
    let mut out = [0u32; 3];
    let insert = core::ptr::read_volatile(addr_of!(BYTE_KEY_WORD_TREE_INSERT_UNIQUE));
    insert(addr_of_mut!(out).cast(), map, addr_of!(pair).cast());
    (out[0] as usize as *mut u32).add(5)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const MAP_OFFSET: usize = 0x40;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BYTE_KEY_WORD_MAP_LOOKUP_OR_INSERT, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: std::vec::Vec<(u32, u32, usize)> = std::vec::Vec::new();

    unsafe extern "C" fn recording_insert(out: *mut u32, map: *mut u8, pair: *const u32) {
        (*core::ptr::addr_of_mut!(CALLS)).push((pair.read(), pair.add(1).read(), map as usize));
        out.write((*SLAB).expect("fixture") as u32);
        (out as *mut u8).add(4).write(1);
    }

    struct SeamGuard;

    impl SeamGuard {
        unsafe fn install() -> Self {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(BYTE_KEY_WORD_TREE_INSERT_UNIQUE)
                .write_volatile(recording_insert);
            Self
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BYTE_KEY_WORD_TREE_INSERT_UNIQUE)
                    .write_volatile(missing_byte_key_word_tree_insert_unique);
            }
        }
    }

    #[test]
    fn reads_each_byte_key_and_returns_its_mapped_word_slot() {
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/byte_key_word_map"));
            return;
        };
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { SeamGuard::install() };
        let keys = [0u8, 0xff];
        for key in keys {
            let slot = unsafe {
                byte_key_word_map_lookup_or_insert((slab + MAP_OFFSET) as *mut u8, &key)
            };
            assert_eq!(slot as usize, slab + 0x14);
        }
        let calls = unsafe { (*core::ptr::addr_of!(CALLS)).clone() };
        assert_eq!(calls, std::vec![(0, 0, slab + MAP_OFFSET), (0xff, 0, slab + MAP_OFFSET)]);
    }
}
