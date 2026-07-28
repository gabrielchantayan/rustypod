//! The two accessors for the **state-flag word at +0x44** of the
//! 0x081fbxxx state-machine class — `FUN_081fc3f4` @ 0x081fc3f4 and
//! `FUN_081fc524` @ 0x081fc524.
//!
//! Every user of that class reaches its flag word through these two
//! functions (plus open-coded `|=` / `&= ~` in the class's own methods),
//! and always with a single-bit mask. The bits seen at the 34 `bl` sites
//! of the test accessor:
//!
//! ```text
//! 0x00000001  20x   0x00040000  20x   0x00080000   1x
//! 0x00010000   4x   0x00020000   2x   0x00100000   1x
//! ```
//!
//! The owning class is not otherwise identified; what the surrounding
//! code shows is a progress/completion state machine with a parent
//! object at +0x04 that it notifies by code (`FUN_0818a41c(parent,
//! code, self)` with codes 5, 7 and 10) and a pair of counters at +0x18
//! and +0x1c / +0x50 compared as "produced <= expected". For example
//! `FUN_081fc230`:
//!
//! ```c
//! if (state_flags_contain(self, 0x1) && self->+0x18 <= self->+0x50) {
//!     if (state_flags_set(self, 0x100000) == 0)   // first time only
//!         notify(self->parent, 7, self);
//!     return 1;
//! }
//! ```
//!
//! Faithful details:
//! - The test is `bics r0, mask, flags` — it asks whether the flag word
//!   contains **all** bits of the mask, not whether it shares any. With
//!   the single-bit masks every call site uses the two coincide, but the
//!   multi-bit behavior is the original's and is reproduced.
//! - [`state_flags_set`] is a plain non-atomic read/modify/write: it
//!   loads, ANDs for the result, ORs, stores. No lock, no interrupt
//!   guard, no LDREX. Callers use its return value as a "was already
//!   set" answer (`FUN_081fc408` tests `!= 0x10000`), which is exactly
//!   `fetch_or` semantics — but only as long as nothing races it, which
//!   is the original's contract too.
//! - The flag word is addressed by literal byte offset into a `*mut u8`
//!   (the `drivers/surface.rs` precedent): it is a `u32`, not a pointer,
//!   so nothing shifts on a 64-bit test host.

/// Byte offset of the state-flag word inside the object.
const STATE_FLAGS: usize = 0x44;

#[inline(always)]
unsafe fn flags(object: *mut u8) -> u32 {
    (object.add(STATE_FLAGS) as *const u32).read_volatile()
}

/// state_flags_contain — original: `FUN_081fc3f4` @ 0x081fc3f4
/// (20 bytes; 34 `bl` call sites from 20 distinct callers).
///
/// Returns 1 when the object's state word holds **every** bit of
/// `mask`, else 0 (`bics` + `movne`/`moveq`). An empty mask is
/// vacuously contained and returns 1, as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn state_flags_contain(object: *mut u8, mask: u32) -> u32 {
    u32::from(mask & !flags(object) == 0)
}

/// state_flags_set — original: `FUN_081fc524` @ 0x081fc524 (24 bytes;
/// 3 `bl` call sites).
///
/// Sets every bit of `mask` in the object's state word and returns the
/// subset of `mask` that was **already** set — a non-atomic `fetch_or`,
/// so a zero result means "this call is the one that set it".
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn state_flags_set(object: *mut u8, mask: u32) -> u32 {
    let previous = flags(object);
    (object.add(STATE_FLAGS) as *mut u32).write_volatile(previous | mask);
    previous & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for the object: byte-addressed, word-aligned.
    #[repr(align(4))]
    struct Object([u8; 0x60]);

    impl Object {
        fn with_flags(value: u32) -> Self {
            let mut object = Object([0xa5; 0x60]);
            object.0[STATE_FLAGS..STATE_FLAGS + 4].copy_from_slice(&value.to_le_bytes());
            object
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn flags(&self) -> u32 {
            u32::from_le_bytes(self.0[STATE_FLAGS..STATE_FLAGS + 4].try_into().unwrap())
        }
    }

    /// The mask values the 34 call sites actually pass.
    const LIVE_MASKS: [u32; 6] = [0x1, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000];

    #[test]
    fn a_single_bit_is_reported_exactly_when_it_is_set() {
        for mask in LIVE_MASKS {
            let mut absent = Object::with_flags(!mask);
            assert_eq!(unsafe { state_flags_contain(absent.ptr(), mask) }, 0, "{mask:#x}");

            let mut present = Object::with_flags(mask);
            assert_eq!(unsafe { state_flags_contain(present.ptr(), mask) }, 1, "{mask:#x}");
        }
    }

    #[test]
    fn a_multi_bit_mask_needs_every_bit() {
        let mut object = Object::with_flags(0x30000);
        assert_eq!(unsafe { state_flags_contain(object.ptr(), 0x30000) }, 1);
        assert_eq!(unsafe { state_flags_contain(object.ptr(), 0x10000) }, 1);
        // Partial overlap is NOT containment — this is the `bics`
        // semantics, not "any bit in common".
        assert_eq!(unsafe { state_flags_contain(object.ptr(), 0x30001) }, 0);
    }

    #[test]
    fn the_empty_mask_is_vacuously_contained() {
        let mut object = Object::with_flags(0);
        assert_eq!(unsafe { state_flags_contain(object.ptr(), 0) }, 1);
    }

    #[test]
    fn the_all_ones_mask_needs_all_ones() {
        let mut full = Object::with_flags(0xffff_ffff);
        assert_eq!(unsafe { state_flags_contain(full.ptr(), 0xffff_ffff) }, 1);
        let mut nearly = Object::with_flags(0xffff_fffe);
        assert_eq!(unsafe { state_flags_contain(nearly.ptr(), 0xffff_ffff) }, 0);
    }

    #[test]
    fn only_the_word_at_0x44_is_read() {
        let mut object = Object::with_flags(0);
        // Every other byte is 0xa5 and must not leak into the answer.
        assert_eq!(unsafe { state_flags_contain(object.ptr(), 0x1) }, 0);
        assert_eq!(unsafe { state_flags_contain(object.ptr(), 0xa5a5_a5a5) }, 0);
    }

    #[test]
    fn setting_reports_the_bits_that_were_already_there() {
        let mut object = Object::with_flags(0x10000);
        assert_eq!(unsafe { state_flags_set(object.ptr(), 0x10000) }, 0x10000);
        assert_eq!(unsafe { state_flags_set(object.ptr(), 0x100000) }, 0);
        assert_eq!(object.flags(), 0x110000);
    }

    #[test]
    fn setting_is_idempotent_and_the_second_call_reports_it() {
        let mut object = Object::with_flags(0);
        assert_eq!(unsafe { state_flags_set(object.ptr(), 0x100000) }, 0);
        assert_eq!(unsafe { state_flags_set(object.ptr(), 0x100000) }, 0x100000);
        assert_eq!(object.flags(), 0x100000);
    }

    #[test]
    fn the_returned_subset_is_masked_not_the_whole_word() {
        let mut object = Object::with_flags(0xffff_ffff);
        assert_eq!(unsafe { state_flags_set(object.ptr(), 0x40000) }, 0x40000);
    }

    #[test]
    fn a_partly_present_mask_reports_only_the_present_part() {
        let mut object = Object::with_flags(0x20000);
        assert_eq!(unsafe { state_flags_set(object.ptr(), 0x60000) }, 0x20000);
        assert_eq!(object.flags(), 0x60000);
    }

    #[test]
    fn setting_the_empty_mask_changes_nothing() {
        let mut object = Object::with_flags(0x1234);
        assert_eq!(unsafe { state_flags_set(object.ptr(), 0) }, 0);
        assert_eq!(object.flags(), 0x1234);
    }

    #[test]
    fn set_and_contain_agree_after_a_set() {
        let mut object = Object::with_flags(0);
        for mask in LIVE_MASKS {
            unsafe { state_flags_set(object.ptr(), mask) };
            assert_eq!(unsafe { state_flags_contain(object.ptr(), mask) }, 1, "{mask:#x}");
        }
        let all = LIVE_MASKS.iter().fold(0, |acc, mask| acc | mask);
        assert_eq!(object.flags(), all);
        assert_eq!(unsafe { state_flags_contain(object.ptr(), all) }, 1);
    }

    #[test]
    fn the_setter_leaves_the_neighbouring_bytes_alone() {
        let mut object = Object::with_flags(0);
        unsafe { state_flags_set(object.ptr(), 0xffff_ffff) };
        for offset in 0..0x60 {
            if (STATE_FLAGS..STATE_FLAGS + 4).contains(&offset) {
                continue;
            }
            assert_eq!(object.0[offset], 0xa5, "byte +{offset:#x}");
        }
    }
}
