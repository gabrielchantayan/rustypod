//! `slot_table_clear` — original: `FUN_081fea54` @ 0x081fea54
//! (52 bytes; 10 `bl` call sites, binary-scanned).
//!
//! Releases one entry of the 17-slot registration table @ 0x08ac8b94.
//! The whole family shares that base:
//!
//! - `FUN_081ff758` builds it: `memset(table, 0, 0x110)` — 17 × 16
//!   bytes exactly — then seeds every slot's +4 word with 0x7fffffff.
//! - `FUN_081fe954` registers a slot: rejects `index >= 17` *or*
//!   `kind >= 3` with error 9, and, only if the slot is still free
//!   (byte +0 == 0), stores `kind`/`value_a`/`value_b` into +4/+8/+0xc
//!   with one `stmib` and raises the occupied byte.
//! - this function releases one: restores +4 to 0x7fffffff, zeroes
//!   +8/+0xc, and drops the occupied byte.
//!
//! Every call site pairs the two: `if (enabled) register(this, SLOT,
//! kind, a, b); else slot_table_clear(this, SLOT);` with `SLOT` a
//! compile-time constant (10 and 16 both appear), so the index is a
//! slot *id*, not a loop variable.
//!
//! ```text
//! slot +0x0  u8   occupied — 0 free, 1 registered
//! slot +0x4  i32  kind     — 0..2 when registered, 0x7fffffff = free
//! slot +0x8  u32  value_a
//! slot +0xc  u32  value_b
//! ```
//!
//! Faithful details:
//! - The first argument is a `this` the original never reads (`mov r0,
//!   #9` / `mov r0, #0` kill it immediately). Kept because all 10 call
//!   sites pass it.
//! - The bounds test is `cmp r1, #17` + `bxge lr`, a **signed**
//!   comparison: only `index >= 17` is refused. A negative index would
//!   index before the table and corrupt memory, on device exactly as
//!   here; the port reproduces the test rather than hardening it. Every
//!   call site passes a constant in range.
//! - Store order (+4, +8, +0xc, then the byte at +0) is preserved.
//!
//! Deviation (block_mgr.rs precedent): the table is the crate static
//! [`SLOTS`] rather than living at 0x08ac8b94, which is past the end of
//! the decrypted image (pure runtime RAM). Every field is 32-bit or a
//! byte, so the 16-byte target stride holds on a 64-bit host too.

/// Slots in the table (`0x110 / 16`, and the `cmp #17` bound).
pub const SLOT_COUNT: usize = 17;

/// The `kind` value a free slot carries (`mvn r2, #0x80000000`).
pub const SLOT_KIND_FREE: i32 = 0x7fff_ffff;

/// Error returned for an index at or past [`SLOT_COUNT`].
pub const SLOT_INDEX_OUT_OF_RANGE: u32 = 9;

/// One 16-byte registration slot.
#[repr(C)]
pub struct Slot {
    /// +0x0: 0 free, 1 registered.
    pub occupied: u8,
    /// +0x1..+0x3: never touched.
    pub reserved: [u8; 3],
    /// +0x4: 0..2 while registered, [`SLOT_KIND_FREE`] while free.
    pub kind: i32,
    /// +0x8: first payload word.
    pub value_a: u32,
    /// +0xc: second payload word.
    pub value_b: u32,
}

// Target-exact layout (byte + three words, so it holds on any host).
const _: [u8; 0x04] = [0; core::mem::offset_of!(Slot, kind)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(Slot, value_a)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(Slot, value_b)];
const _: [u8; 0x10] = [0; core::mem::size_of::<Slot>()];

/// A free slot, as `FUN_081ff758` leaves every entry at startup.
const FREE_SLOT: Slot =
    Slot { occupied: 0, reserved: [0; 3], kind: SLOT_KIND_FREE, value_a: 0, value_b: 0 };

/// The registration table (original: the fixed base 0x08ac8b94 — see
/// the module-header deviation).
pub static mut SLOTS: [Slot; SLOT_COUNT] = [FREE_SLOT; SLOT_COUNT];

/// slot_table_clear — original: `FUN_081fea54` @ 0x081fea54
/// (52 bytes).
///
/// Releases slot `index`, returning 0. An `index` of 17 or more is
/// refused with [`SLOT_INDEX_OUT_OF_RANGE`] and nothing is written.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_table_clear(_this: *mut u8, index: i32) -> u32 {
    if index >= SLOT_COUNT as i32 {
        return SLOT_INDEX_OUT_OF_RANGE;
    }
    // Volatile: the table's other users are unported (the registrar
    // @ 0x081fe954 and the builder @ 0x081ff758), so nothing in this
    // crate reads it — plain stores get eliminated as dead.
    let slot = (core::ptr::addr_of_mut!(SLOTS) as *mut Slot).offset(index as isize);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot).kind), SLOT_KIND_FREE);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot).value_a), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot).value_b), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot).occupied), 0);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes the tests that mutate the global slot table.
    static SLOTS_LOCK: Mutex<()> = Mutex::new(());

    /// Marks `index` registered with recognizable contents and hands
    /// back the guard.
    fn with_registered(index: usize) -> MutexGuard<'static, ()> {
        let guard = SLOTS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let slot = slot(index);
            (*slot).occupied = 1;
            (*slot).kind = 2;
            (*slot).value_a = 0xaaaa_aaaa;
            (*slot).value_b = 0xbbbb_bbbb;
        }
        guard
    }

    /// Restores the startup state. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            for index in 0..SLOT_COUNT {
                let s = slot(index);
                (*s).occupied = 0;
                (*s).kind = SLOT_KIND_FREE;
                (*s).value_a = 0;
                (*s).value_b = 0;
            }
        }
        drop(guard);
    }

    fn slot(index: usize) -> *mut Slot {
        unsafe { (ptr::addr_of_mut!(SLOTS) as *mut Slot).add(index) }
    }

    fn clear(index: i32) -> u32 {
        unsafe { slot_table_clear(ptr::null_mut(), index) }
    }

    #[test]
    fn clearing_a_registered_slot_restores_the_free_state() {
        let guard = with_registered(4);
        assert_eq!(clear(4), 0);
        unsafe {
            assert_eq!((*slot(4)).occupied, 0);
            assert_eq!((*slot(4)).kind, 0x7fff_ffff);
            assert_eq!((*slot(4)).value_a, 0);
            assert_eq!((*slot(4)).value_b, 0);
        }
        restore(guard);
    }

    #[test]
    fn clearing_an_already_free_slot_is_a_no_op_that_still_returns_zero() {
        let guard = SLOTS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(clear(0), 0);
        unsafe { assert_eq!((*slot(0)).kind, 0x7fff_ffff) };
        restore(guard);
    }

    #[test]
    fn the_first_and_last_indices_are_both_in_range() {
        let guard = with_registered(0);
        unsafe {
            (*slot(SLOT_COUNT - 1)).occupied = 1;
            (*slot(SLOT_COUNT - 1)).kind = 1;
        }
        assert_eq!(clear(0), 0);
        assert_eq!(clear(SLOT_COUNT as i32 - 1), 0);
        unsafe {
            assert_eq!((*slot(0)).occupied, 0);
            assert_eq!((*slot(SLOT_COUNT - 1)).occupied, 0);
        }
        restore(guard);
    }

    #[test]
    fn index_seventeen_and_beyond_is_refused_without_writing() {
        let guard = with_registered(16);
        assert_eq!(clear(SLOT_COUNT as i32), SLOT_INDEX_OUT_OF_RANGE);
        assert_eq!(clear(1000), SLOT_INDEX_OUT_OF_RANGE);
        assert_eq!(clear(i32::MAX), SLOT_INDEX_OUT_OF_RANGE);
        unsafe {
            assert_eq!((*slot(16)).occupied, 1, "the in-range slot is untouched");
            assert_eq!((*slot(16)).value_a, 0xaaaa_aaaa);
        }
        restore(guard);
    }

    #[test]
    fn clearing_one_slot_leaves_its_neighbours_alone() {
        let guard = with_registered(8);
        unsafe {
            (*slot(7)).occupied = 1;
            (*slot(7)).value_a = 0x7777_7777;
            (*slot(9)).occupied = 1;
            (*slot(9)).value_a = 0x9999_9999;
        }
        assert_eq!(clear(8), 0);
        unsafe {
            assert_eq!((*slot(7)).occupied, 1);
            assert_eq!((*slot(7)).value_a, 0x7777_7777);
            assert_eq!((*slot(9)).occupied, 1);
            assert_eq!((*slot(9)).value_a, 0x9999_9999);
        }
        restore(guard);
    }

    #[test]
    fn the_this_argument_is_ignored() {
        let guard = with_registered(2);
        let mut anything = [0u8; 4];
        assert_eq!(unsafe { slot_table_clear(anything.as_mut_ptr(), 2) }, 0);
        unsafe { assert_eq!((*slot(2)).occupied, 0) };
        restore(guard);
    }
}
