//! `tag_handler_register_default` — original: `FUN_081e11a8` @
//! **0x081e11a8** (52 bytes of code + one trailing literal-pool word @
//! `0x081e11dc` = **56 bytes** of true extent, `0x081e11a8..0x081e11e0`;
//! the next function — the registrar `FUN_081e11e0` — opens
//! `push {r4, lr}` (`e92d4010`) @ `0x081e11e0`. The dropped pool word is
//! the BSS map global `0x08ad7d74`, reached by both
//! `ldr r0, [pc, #36]` / `ldr r0, [pc, #12]`). **22 `bl` call sites, all
//! unconditional — 0 predicated, 0 plain `b`** — binary-verified by
//! decoding every B/BL word in `work/firmware/osos.dec` (Ghidra's 22
//! confirmed). Every one sits inside the registrar `FUN_081e11e0` @
//! `0x081e11e0` (itself called once, from `0x08143ac8`), which registers
//! eleven big-endian fourcc tags — `"albm"`, `"aclk"`, `"bmdg"`,
//! `"calv"`, `"cpct"`, `"capt"`, `"sbtl"`, `"date"`, `"imag"`, `"imgc"`,
//! `"imgg"` (literal words @ `0x081e12fc..0x081e1350`, interleaved
//! tag/handler pairs) — against handler entry points.
//!
//! ```text
//! 081e11a8  push {r0, r1, r4, lr}   @ frame: [sp] = tag key slot
//! 081e11ac  mov  r4, r1             @ r4 = handler
//! 081e11b0  ldr  r0, [pc, #36]      @ = 0x08ad7d74 (pool @ 0x081e11dc)
//! 081e11b4  mov  r1, sp             @ &key
//! 081e11b8  bl   0x083dbd9c         @ slot = tag_map_value_slot(map,&key)
//! 081e11bc  ldr  r0, [r0]           @ *slot
//! 081e11c0  cmp  r0, #0
//! 081e11c4  bne  0x081e11d8         @ occupied -> keep existing handler
//! 081e11c8  ldr  r0, [pc, #12]      @ = 0x08ad7d74
//! 081e11cc  mov  r1, sp
//! 081e11d0  bl   0x083dbd9c         @ slot = tag_map_value_slot(map,&key)
//! 081e11d4  str  r4, [r0]           @ *slot = handler
//! 081e11d8  pop  {r2, r3, r4, pc}
//! 081e11dc  .word 0x08ad7d74
//! ```
//!
//! Algorithm: in the global tag→handler map rooted at the BSS object
//! `0x08ad7d74` (past the decrypted image end `0x08a1b5e8`, so
//! runtime-zeroed BSS, matching the map constructor @ `0x083dbe5c`'s
//! all-zero stores), find-or-create the node for `tag` and read its
//! value slot; only when the slot is 0 is `handler` stored — a
//! set-if-unset ("register default") that lets a pre-existing
//! registration win. The callee `FUN_083dbd9c` @ `0x083dbd9c` is the
//! ADS `std::map<u32, u32>` find-or-insert: it runs the tree walk @
//! `0x083ce874` (comparator @ `0x083d7598` = a plain `u32` less-than on
//! both dereferenced key words, left link `+8`, right link `+0xc`, key @
//! node `+0x10`) and returns `node + 0x14`, the mapped-value address.
//! Both the original and this port call it twice on the store path —
//! the map may rebalance on insert, so the slot address is re-fetched
//! rather than reused. The sibling getter `FUN_081e13b4` @ `0x081e13b4`
//! (same map global, same callee, called from `0x081e9b5c`) reads the
//! slot and `blx`s the handler with the tag's owner object in r3, so
//! the stored word is a raw handler entry-point address.
//!
//! ## Deviations
//!
//! The map find-or-insert @ `0x083dbd9c` is unported (the ADS tree
//! insert/rebalance machinery @ `0x083cea3c`/`0x083cf998` underneath is
//! not yet characterized), so it rides the [`TAG_MAP_VALUE_SLOT`]
//! dispatch slot, read through `read_volatile` (the
//! `UPDATE_DISPATCH_OPS` house pattern): on target the default
//! transmutes the ROM address `0x083dbd9c`, so a hooked build is
//! faithful; on host the default is a documented inert stub returning
//! one shared zero word (every key aliases it), and the tests install a
//! real find-or-insert model. The map global address `0x08ad7d74` is
//! passed through as an opaque pointer exactly like the original's
//! literal-pool load; on host it is never dereferenced.

use core::ptr;

/// BSS global: the tag→handler map object (the original's pool word @
/// `0x081e11dc`; past the image end, runtime-zeroed).
pub const TAG_HANDLER_MAP_ADDRESS: usize = 0x08ad_7d74;

/// Firmware load address of the unported map find-or-insert callee,
/// kept beside the transmute below.
pub const TAG_MAP_VALUE_SLOT_ADDRESS: usize = 0x083d_bd9c;

/// The map find-or-insert (original @ `0x083dbd9c`): given the map
/// object and a pointer to the key word, returns the address of the
/// mapped-value slot (`node + 0x14`), inserting a zero-valued node when
/// the key is absent. Never returns NULL.
pub type TagMapValueSlot = unsafe extern "C" fn(map: *mut u8, key: *const u32) -> *mut u32;

/// Target default: the ROM map find-or-insert.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_tag_map_value_slot(map: *mut u8, key: *const u32) -> *mut u32 {
    let f: TagMapValueSlot = core::mem::transmute(TAG_MAP_VALUE_SLOT_ADDRESS);
    f(map, key)
}

/// One shared word behind the host default stub.
#[cfg(not(target_os = "none"))]
static mut STUB_SLOT: u32 = 0;

/// Host default: inert — every key aliases the same zero word, so the
/// default port stores into scratch space only. The tests install a
/// real find-or-insert model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_tag_map_value_slot(
    _map: *mut u8,
    _key: *const u32,
) -> *mut u32 {
    ptr::addr_of_mut!(STUB_SLOT) as *mut u32
}

/// The active map find-or-insert. Host tests swap in a recording model
/// and restore; the real port replaces the default when it lands.
pub static mut TAG_MAP_VALUE_SLOT: TagMapValueSlot = firmware_tag_map_value_slot;

/// tag_handler_register_default — original: `FUN_081e11a8` @
/// `0x081e11a8` (see the module header for the full listing, extent
/// correction and call-count verification).
///
/// Registers `handler` for `tag` in the global tag→handler map unless
/// an entry is already present: find-or-create the node, and store only
/// when the current value is 0. The slot address is re-fetched for the
/// store (the original's second `bl 0x083dbd9c`), never reused across
/// the possible insert.
///
/// # Safety
///
/// [`TAG_MAP_VALUE_SLOT`] must be callable and must return a writable
/// word for the key (the original dereferences it unconditionally).
/// `tag` is copied into a stack slot whose address is handed to the
/// callee, matching the original's `push {r0, r1}` frame.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tag_handler_register_default(tag: u32, handler: u32) {
    let key = tag;
    let key_ptr = ptr::addr_of!(key);
    let map = TAG_HANDLER_MAP_ADDRESS as *mut u8;
    let slot_get = ptr::read_volatile(ptr::addr_of!(TAG_MAP_VALUE_SLOT));
    let slot = slot_get(map, key_ptr);
    if slot.read() == 0 {
        // Second call, exactly like the original: an insert may
        // rebalance the tree, so the slot address is re-fetched.
        let slot_get = ptr::read_volatile(ptr::addr_of!(TAG_MAP_VALUE_SLOT));
        let slot = slot_get(map, key_ptr);
        slot.write(handler);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that swaps the seam slot and the model
    /// table (the cxx/settings.rs SETTINGS_LOCK pattern).
    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    /// The model map: (key, value) pairs; a zero key is an empty entry.
    static mut MODEL_TABLE: [(u32, u32); 8] = [(0, 0); 8];

    /// Every (map, key) pair the model was called with, in order.
    static mut SLOT_CALLS: Vec<(usize, u32)> = Vec::new();

    /// Find-or-insert model of `FUN_083dbd9c`: returns the value-slot
    /// address for `key`, claiming a zero-valued entry when absent.
    unsafe extern "C" fn model_value_slot(map: *mut u8, key: *const u32) -> *mut u32 {
        let key_value = key.read();
        (*ptr::addr_of_mut!(SLOT_CALLS)).push((map as usize, key_value));
        let table = &mut *ptr::addr_of_mut!(MODEL_TABLE);
        let mut free: Option<usize> = None;
        for (index, entry) in table.iter_mut().enumerate() {
            if entry.0 == key_value {
                return ptr::addr_of_mut!(entry.1);
            }
            if entry.0 == 0 && free.is_none() {
                free = Some(index);
            }
        }
        let index = free.expect("model table full");
        table[index] = (key_value, 0);
        ptr::addr_of_mut!(table[index].1)
    }

    struct SeamGuard(MutexGuard<'static, ()>);

    /// Resets the model and installs it over the seam; restores on drop.
    fn install_model() -> SeamGuard {
        let guard = SEAM_LOCK.lock();
        unsafe {
            *ptr::addr_of_mut!(MODEL_TABLE) = [(0, 0); 8];
            (*ptr::addr_of_mut!(SLOT_CALLS)).clear();
            TAG_MAP_VALUE_SLOT = model_value_slot;
        }
        SeamGuard(guard)
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe { TAG_MAP_VALUE_SLOT = firmware_tag_map_value_slot };
        }
    }

    fn calls() -> Vec<(usize, u32)> {
        unsafe { (*ptr::addr_of!(SLOT_CALLS)).clone() }
    }

    fn value_of(tag: u32) -> Option<u32> {
        unsafe {
            (*ptr::addr_of!(MODEL_TABLE))
                .iter()
                .find(|entry| entry.0 == tag)
                .map(|entry| entry.1)
        }
    }

    #[test]
    fn unset_tag_stores_handler_with_two_lookups() {
        let _guard = install_model();
        unsafe { tag_handler_register_default(0x6461_7465, 0x081d_2670) }; // "date"
        assert_eq!(value_of(0x6461_7465), Some(0x081d_2670));
        // Both lookups pass the BSS map global and the key by pointer.
        assert_eq!(
            calls(),
            std::vec![
                (TAG_HANDLER_MAP_ADDRESS, 0x6461_7465),
                (TAG_HANDLER_MAP_ADDRESS, 0x6461_7465)
            ]
        );
    }

    #[test]
    fn occupied_tag_keeps_existing_handler() {
        let _guard = install_model();
        unsafe {
            tag_handler_register_default(0x616c_626d, 0x081d_4854); // "albm"
            tag_handler_register_default(0x616c_626d, 0xdead_beef);
        }
        // The second registration must not overwrite, and must not even
        // re-fetch the slot (one lookup on the occupied path).
        assert_eq!(value_of(0x616c_626d), Some(0x081d_4854));
        assert_eq!(
            calls(),
            std::vec![
                (TAG_HANDLER_MAP_ADDRESS, 0x616c_626d),
                (TAG_HANDLER_MAP_ADDRESS, 0x616c_626d),
                (TAG_HANDLER_MAP_ADDRESS, 0x616c_626d)
            ]
        );
    }

    #[test]
    fn zero_handler_is_still_stored() {
        let _guard = install_model();
        // The original's branch tests the CURRENT value, not the new
        // one: storing 0 into an empty slot still performs the write
        // (second lookup runs).
        unsafe { tag_handler_register_default(0x696d_6167, 0) }; // "imag"
        assert_eq!(value_of(0x696d_6167), Some(0));
        assert_eq!(calls().len(), 2);
    }

    #[test]
    fn distinct_tags_get_distinct_slots() {
        let _guard = install_model();
        unsafe {
            tag_handler_register_default(0x696d_6763, 0x0820_3efc); // "imgc"
            tag_handler_register_default(0x696d_6767, 0x081d_ed90); // "imgg"
        }
        assert_eq!(value_of(0x696d_6763), Some(0x0820_3efc));
        assert_eq!(value_of(0x696d_6767), Some(0x081d_ed90));
    }
}
