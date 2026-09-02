//! `context_activity_enter` — original: `FUN_082dd3d8` @ 0x082dd3d8 (36
//! bytes).
//!
//! Raw ARM body, decoded from `osos.dec`:
//!
//! ```text
//! ldr  r1, [r0, #0xe0]      @ activity = context->activity
//! add  r1, r1, #1
//! str  r1, [r0, #0xe0]      @ context->activity = activity + 1
//! ldr  r2, [r0, #0xdc]      @ marked  = context->marked
//! cmp  r2, #0
//! bxeq lr                   @ unmarked: done
//! cmp  r1, #1
//! streq r1, [r0, #0xe0]     @ marked && became 1: store 1 again
//! bx   lr
//! ```
//!
//! The next separately linked function begins at 0x082dd3fc (`push
//! {r4-r10, lr}`), so the 36-byte extent is exact; no trailing literal
//! pool. Decoding every ARM B/BL word in `osos.dec` finds exactly 24
//! direct call sites, all unconditional plain `bl` (no predicated forms,
//! no tail `b`); the address occurs in no image data word, so binding is
//! static, never virtual.
//!
//! This is the enter half of the context activity lease on the C++
//! context object: callers bump the u32 activity count at +0xe0 on entry
//! and decrement it inline (`[ctx+0xe0] -= 1`) on exit — e.g.
//! FUN_0837dc38 wraps FUN_082dd05c that way, and `release_object` @
//! 0x0837ee98 (ported in `cxx/release.rs`) takes the same lease through
//! this function. The u32 at +0xdc is a mark flag: FUN_0837e920 sets it
//! to 1 on every context in the global registry list (linked at +0xd4)
//! before an idle-context sweep and clears it afterwards.
//!
//! The final `streq` re-stores the value 1 that the first `str` already
//! wrote — semantically a no-op, yet ADS emitted it, which is only
//! possible if both fields are `volatile int` in the source (a volatile
//! store may not be elided). The port therefore uses volatile accesses,
//! keeping the redundant store observable to the memory system exactly as
//! the original.
//!
//! Algorithm: increment the volatile activity count at +0xe0 (wrapping);
//! if the volatile mark flag at +0xdc is nonzero and the new count is 1,
//! volatile-store 1 into +0xe0 a second time. Deliberate deviations:
//! none. A dedicated link section prevents identical-code folding against
//! any future counter-bump port.

/// Volatile u32 activity count of the context object.
const CONTEXT_ACTIVITY: usize = 0xe0;
/// Volatile u32 sweep-mark flag of the context object.
const CONTEXT_MARKED: usize = 0xdc;

/// Enters one activity lease on `context`: increments the activity count
/// at +0xe0 and, when the sweep mark at +0xdc is set and the count
/// transitioned to 1, re-stores 1 (a volatile, non-elidable store).
///
/// The original performs no NULL check: `context` must point at a live
/// context object with valid u32 words at +0xdc and +0xe0.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_activity_enter")]
#[inline(never)]
pub unsafe extern "C" fn context_activity_enter(context: *mut u8) {
    let activity = context.add(CONTEXT_ACTIVITY) as *mut u32;
    let entered = activity.read_volatile().wrapping_add(1);
    activity.write_volatile(entered);
    let marked = (context.add(CONTEXT_MARKED) as *const u32).read_volatile();
    if marked == 0 {
        return;
    }
    if entered == 1 {
        // Volatile re-store of the value already written: ADS emitted the
        // streq, so the source field was volatile and the store survives.
        activity.write_volatile(entered);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a 0x100-byte context fixture filled with a sentinel, with
    /// the given mark flag at +0xdc and activity count at +0xe0.
    struct ContextFixture {
        bytes: [u8; 0x100],
    }

    impl ContextFixture {
        fn new(marked: u32, activity: u32) -> Self {
            let mut fixture = ContextFixture { bytes: [0xa5u8; 0x100] };
            fixture.set_word(CONTEXT_MARKED, marked);
            fixture.set_word(CONTEXT_ACTIVITY, activity);
            fixture
        }

        fn set_word(&mut self, offset: usize, value: u32) {
            self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn word(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
        }

        fn enter(&mut self) {
            unsafe { context_activity_enter(self.bytes.as_mut_ptr()) }
        }

        /// Only +0xe0 may differ from the freshly built fixture.
        fn assert_untouched_except_activity(&self, before: &ContextFixture) {
            for offset in (0..0x100usize).step_by(4) {
                if offset == CONTEXT_ACTIVITY {
                    continue;
                }
                assert_eq!(
                    self.word(offset),
                    before.word(offset),
                    "word at {offset:#x} must not be modified"
                );
            }
        }
    }

    #[test]
    fn increments_activity_when_unmarked() {
        let mut fixture = ContextFixture::new(0, 41);
        let before = ContextFixture::new(0, 41);

        fixture.enter();

        assert_eq!(fixture.word(CONTEXT_ACTIVITY), 42);
        assert_eq!(fixture.word(CONTEXT_MARKED), 0, "the mark flag is read-only");
        fixture.assert_untouched_except_activity(&before);
    }

    #[test]
    fn increments_activity_when_marked_and_result_is_not_one() {
        for initial in [1u32, 2, 0x7fff_ffff, 0xffff_fffe] {
            let mut fixture = ContextFixture::new(1, initial);
            let before = ContextFixture::new(1, initial);

            fixture.enter();

            assert_eq!(
                fixture.word(CONTEXT_ACTIVITY),
                initial.wrapping_add(1),
                "initial {initial:#x}"
            );
            fixture.assert_untouched_except_activity(&before);
        }
    }

    #[test]
    fn marked_transition_to_one_stores_one() {
        let mut fixture = ContextFixture::new(1, 0);
        let before = ContextFixture::new(1, 0);

        fixture.enter();

        assert_eq!(fixture.word(CONTEXT_ACTIVITY), 1);
        fixture.assert_untouched_except_activity(&before);
    }

    #[test]
    fn any_nonzero_mark_enables_the_transition_check() {
        // The ARM compares the flag against 0 only; it is not a boolean.
        for marked in [2u32, 0xffff_ffff] {
            let mut fixture = ContextFixture::new(marked, 0);

            fixture.enter();

            assert_eq!(
                fixture.word(CONTEXT_ACTIVITY),
                1,
                "marked={marked:#x} still takes the entered==1 path"
            );
            assert_eq!(fixture.word(CONTEXT_MARKED), marked);
        }
    }

    #[test]
    fn wraps_at_u32_max_without_taking_the_transition_path() {
        // entered == 0 after wrap, so the streq path is not taken even
        // when marked.
        let mut fixture = ContextFixture::new(1, u32::MAX);

        fixture.enter();

        assert_eq!(fixture.word(CONTEXT_ACTIVITY), 0);
        assert_eq!(fixture.word(CONTEXT_MARKED), 1);
    }

    #[test]
    fn unmarked_never_stores_twice_regression_boundary() {
        // entered == 1 with a clear mark: the original returns at bxeq lr
        // before the cmp/streq pair, leaving the single increment store.
        let mut fixture = ContextFixture::new(0, 0);

        fixture.enter();

        assert_eq!(fixture.word(CONTEXT_ACTIVITY), 1);
        assert_eq!(fixture.word(CONTEXT_MARKED), 0);
    }
}
