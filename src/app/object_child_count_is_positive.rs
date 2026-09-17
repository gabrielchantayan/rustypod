//! Positive-count predicate for an object's child record.
//!
//! `object_child_count_is_positive` — original: `FUN_0829e100` @
//! **0x0829e100** (**28 bytes**; **4 direct `bl` call sites, all
//! unconditional**).
//!
//! Raw ARM decoding establishes the exact extent `0x0829e100..0x0829e11c`:
//!
//! ```text
//! 0829e100  ldr r0, [r0, #8]
//! 0829e104  cmp r0, #0
//! 0829e108  ldrne r0, [r0, #4]
//! 0829e10c  cmpne r0, #0
//! 0829e110  movle r0, #0
//! 0829e114  movgt r0, #1
//! 0829e118  bx lr
//! ```
//!
//! `0x0829e11c` starts the next distinct push-prologue function. Decoding
//! every A32 `B`/`BL` word in `osos.dec` finds incoming plain `bl` calls at
//! `0x0815fa94`, `0x081b9ef0`, `0x081d1698`, and `0x0829e124`, with no
//! predicated `bl` calls.
//!
//! # Algorithm
//!
//! Read the target-width child pointer at object `+8`. Return one only when it
//! is nonzero and its signed word at `+4` is positive; otherwise return zero.
//!
//! # Deliberate deviations
//!
//! The object and child-record types are unrecovered. Raw `u32` words preserve
//! their verified four-byte target offsets on both ARM and 64-bit hosts.
//! LLVM emits an equivalent null early-return and frame prologue instead of
//! retailOS's predicated load and moves; `match.py` confirms the shared load,
//! comparison, and positive-result structure.

/// Returns whether `object` has a child record with a positive signed count.
///
/// # Safety
///
/// `object` must point to an aligned, readable target-layout object containing
/// a `u32` child pointer at offset `+8`. If nonzero, that pointer must identify
/// an aligned, readable child record with an `i32` count at offset `+4`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_child_count_is_positive(object: *const u32) -> u32 {
    let child = unsafe { object.add(2).read() } as *const u32;
    let count = if child.is_null() {
        0
    } else {
        unsafe { child.add(1).read() as i32 }
    };
    (count > 0) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const OBJECT_OFFSET: usize = 0;
    const CHILD_OFFSET: usize = 0x100;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OBJECT_CHILD_COUNT_IS_POSITIVE, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn with_fixture(test: impl FnOnce(*mut u32, *mut u32)) {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/object_child_count_is_positive"));
            return;
        };
        let base = base as *mut u8;
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            test(
                base.add(OBJECT_OFFSET).cast(),
                base.add(CHILD_OFFSET).cast(),
            );
        }
    }

    #[test]
    fn null_child_is_not_positive() {
        with_fixture(|object, _| unsafe {
            object.add(2).write(0);
            assert_eq!(object_child_count_is_positive(object), 0);
        });
    }

    #[test]
    fn signed_count_boundaries_match_retailos() {
        for (count, expected) in [
            (i32::MIN, 0),
            (-1, 0),
            (0, 0),
            (1, 1),
            (i32::MAX, 1),
        ] {
            with_fixture(|object, child| unsafe {
                object.add(2).write(child as usize as u32);
                child.add(1).write(count as u32);
                assert_eq!(object_child_count_is_positive(object), expected, "count {count}");
            });
        }
    }
}
