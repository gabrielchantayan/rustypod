//! `u32_map_value_slot` — original: `FUN_083dbd9c` @ **0x083dbd9c**
//! (**56 bytes**, exactly `0x083dbd9c..0x083dbdd4`; the next separately
//! linked function opens `stmdb sp!, {r3, lr}` (`e92d4008`) @
//! `0x083dbdd4`. Ghidra's 56-byte extent is correct).
//!
//! Decoding every aligned ARM B/BL word in `osos.dec` finds exactly
//! **4 direct, unconditional `bl` call sites** — `0x081e11b8` and
//! `0x081e11d0` inside `tag_handler_register_default` @ `0x081e11a8`,
//! `0x081e13c0` and `0x081e13d8` inside the sibling getter
//! `FUN_081e13b4` @ `0x081e13b4`. There are no predicated calls, direct
//! `b` transfers, or aligned data-word references. The body itself
//! contains exactly **one** `bl` (to the tree walk @ `0x083ce874`) and
//! no predicated calls.
//!
//! ```text
//! 083dbd9c  str lr, [sp, #-0x4]!     @ push lr
//! 083dbda0  ldr r1, [r1, #0x0]       @ key word = *key
//! 083dbda4  sub sp, sp, #0x14
//! 083dbda8  mov r2, #0x0
//! 083dbdac  stmib sp, {r1, r2}       @ pair = {key, 0}   @ sp+4
//! 083dbdb0  mov r1, r0               @ r1 = map
//! 083dbdb4  add r0, sp, #0xc         @ &out
//! 083dbdb8  add r2, sp, #0x4         @ &pair
//! 083dbdbc  bl  0x083ce874           @ tree_walk(&out, map, &pair)
//! 083dbdc0  ldr r0, [sp, #0xc]       @ node = out
//! 083dbdc4  str r0, [sp, #0x0]       @ dead store into the dying frame
//! 083dbdc8  add sp, sp, #0x14
//! 083dbdcc  add r0, r0, #0x14        @ return node + 0x14
//! 083dbdd0  ldr pc, [sp], #0x4       @ pop pc
//! ```
//!
//! Algorithm: the ADS `std::map<u32, u32>` `operator[]` fast path.
//! Given the map object and a pointer to the key word, it materializes
//! a `{key, 0}` pair on the stack, calls the still-retail find-or-insert
//! tree walk @ `0x083ce874` (u32 less-than comparator @ `0x083d7598`,
//! left link `+8`, right link `+0xc`, key @ node `+0x10`; it writes the
//! found-or-freshly-inserted node pointer into `out` plus an inserted
//! flag byte at `out + 4`), and returns `node + 0x14`, the address of
//! the mapped-value slot. Absent keys therefore read back the zero the
//! pair was built with. Never returns NULL.
//!
//! ## Deviations
//!
//! The tree walk @ `0x083ce874` (and the insert/rebalance machinery @
//! `0x083cea3c` / `0x083cf998` beneath it) is not ported, so it rides
//! the [`U32_MAP_TREE_WALK`] dispatch slot read through `read_volatile`
//! (the `UPDATE_DISPATCH_OPS` house pattern): on target the default
//! transmutes the ROM address `0x083ce874`, so a hooked build is
//! faithful; on host the default is a documented panic stub and the
//! tests install a recording model. The original's `str r0, [sp, #0x0]`
//! is a dead store into bytes released by the very next `add sp` — it
//! is unobservable and omitted. The inserted-flag byte the callee
//! writes at `out + 4` is reserved in the Rust `out` frame (matching
//! the original's 12-byte `local_c`) but never read, exactly like the
//! original.

use core::ptr::{addr_of, addr_of_mut};

/// Firmware load address of the still-unported find-or-insert tree
/// walk `FUN_083ce874`.
pub const U32_MAP_TREE_WALK_ADDRESS: usize = 0x083c_e874;

/// ABI of the tree walk. Writes the found-or-inserted node pointer to
/// `out[0]` and an inserted-flag byte at `out + 4`; reads `pair[0]` as
/// the key and copies `pair[1]` into a fresh node's value. `map` is the
/// ADS map object (header pointer at `+0x10`, comparator state at
/// `+0x18`).
pub type U32MapTreeWalk =
    unsafe extern "C" fn(out: *mut u32, map: *mut u8, pair: *const u32);

/// Target default: the ROM tree walk.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_u32_map_tree_walk(
    out: *mut u32,
    map: *mut u8,
    pair: *const u32,
) {
    let walk: U32MapTreeWalk = core::mem::transmute(U32_MAP_TREE_WALK_ADDRESS);
    walk(out, map, pair);
}

/// Host default: inert — the tests install a recording model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_u32_map_tree_walk(
    _out: *mut u32,
    _map: *mut u8,
    _pair: *const u32,
) {
    panic!("u32_map_value_slot requires tree walk 0x083ce874")
}

/// Boundary for the still-retail find-or-insert tree walk at
/// `0x083ce874`. Device builds default to the fixed load address; host
/// tests replace this mutable slot to observe the materialized pair.
#[cfg(target_os = "none")]
pub static mut U32_MAP_TREE_WALK: U32MapTreeWalk = firmware_u32_map_tree_walk;

#[cfg(not(target_os = "none"))]
pub static mut U32_MAP_TREE_WALK: U32MapTreeWalk = missing_u32_map_tree_walk;

/// u32_map_value_slot — original: `FUN_083dbd9c` @ `0x083dbd9c`
/// (56 bytes; 4 direct, unconditional `bl` call sites; one plain `bl`
/// inside the body).
///
/// Builds the `{key, 0}` pair, runs the find-or-insert tree walk, and
/// returns `node + 0x14`, the mapped-value slot for `key`.
///
/// # Safety
///
/// `key` must designate a readable aligned u32 and `map` must be the
/// map object the installed tree walk expects; the returned slot is
/// writable for one u32. As in the original, neither pointer is
/// NULL-checked and the walk's result is dereferenced by callers
/// unconditionally.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn u32_map_value_slot(map: *mut u8, key: *const u32) -> *mut u32 {
    let pair = [key.read(), 0u32];
    // 12 bytes, matching the original's local_c: node pointer plus the
    // inserted-flag byte the walk writes at out + 4.
    let mut out = [0u32; 3];
    let walk = core::ptr::read_volatile(addr_of!(U32_MAP_TREE_WALK));
    walk(addr_of_mut!(out) as *mut u32, map, addr_of!(pair) as *const u32);
    (out[0] as usize as *mut u32).add(5)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::{ptr, vec::Vec};

    /// Slab layout: a stand-in node at +0; the wrapper must return its
    /// address + 0x14. The map object is never dereferenced by the
    /// wrapper itself, so an opaque slab word stands in for it.
    const FIXTURE_LEN: usize = 0x1000;
    const MAP_OFFSET: usize = 0x40;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::U32_MAP_VALUE_SLOT, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(u32, u32, usize)> = Vec::new();

    /// Recording model of the tree walk @ `0x083ce874`: captures the
    /// pair contents and the map pointer, then answers with the slab
    /// node.
    unsafe extern "C" fn recording_walk(out: *mut u32, map: *mut u8, pair: *const u32) {
        let slab = (*SLAB).expect("fixture");
        (*ptr::addr_of_mut!(CALLS)).push((pair.read(), pair.add(1).read(), map as usize));
        out.write(slab as u32);
        // The inserted-flag byte at out + 4 must not corrupt out[0].
        (out as *mut u8).add(4).write(1);
    }

    struct SeamGuard;

    impl SeamGuard {
        unsafe fn install() -> Self {
            (*ptr::addr_of_mut!(CALLS)).clear();
            ptr::addr_of_mut!(U32_MAP_TREE_WALK).write_volatile(recording_walk);
            Self
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(U32_MAP_TREE_WALK).write_volatile(missing_u32_map_tree_walk);
            }
        }
    }

    /// The pair handed to the walk is exactly `{*key, 0}` and the map
    /// pointer passes through untouched; the return is node + 0x14 even
    /// when the walk scribbles its inserted-flag byte at out + 4.
    #[test]
    fn passes_key_pair_and_returns_value_slot() {
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/u32_map_value_slot"));
            return;
        };
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { SeamGuard::install() };
        let key: u32 = 0x6d6c6261; // "albm"
        let slot = unsafe {
            u32_map_value_slot((slab + MAP_OFFSET) as *mut u8, addr_of!(key))
        };
        assert_eq!(slot as usize, slab + 0x14);
        let calls = unsafe { (*ptr::addr_of!(CALLS)).clone() };
        assert_eq!(calls, std::vec![(0x6d6c6261, 0, slab + MAP_OFFSET)]);
    }

    /// The key word is read fresh per call: two distinct keys must each
    /// be observed by the walk, never a cached first key.
    #[test]
    fn reads_key_fresh_per_call() {
        let Some(_slab) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/u32_map_value_slot"));
            return;
        };
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { SeamGuard::install() };
        let first: u32 = 0xdead_beef;
        let second: u32 = 0;
        unsafe {
            u32_map_value_slot(ptr::null_mut(), addr_of!(first));
            u32_map_value_slot(ptr::null_mut(), addr_of!(second));
        }
        let calls = unsafe { (*ptr::addr_of!(CALLS)).clone() };
        assert_eq!(
            calls,
            std::vec![(0xdead_beef, 0, 0usize), (0, 0, 0usize)]
        );
    }
}
