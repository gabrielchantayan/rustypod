//! The ADS C++ one-time-initialization guard pair — `__cxa_guard_acquire`
//! / `__cxa_guard_release` in Itanium/ARM ABI terms.
//!
//! Ports:
//! - `cxa_guard_acquire` — original: `FUN_082ab31c` @ 0x082ab31c
//!   (28 bytes, 172 `bl` call sites, binary-verified). Reads the guard
//!   word: nonzero means the static is already initialized and it
//!   returns 0; zero means this caller wins, and it stores 1 into the
//!   guard *immediately* before returning 1.
//! - `cxa_guard_release` — original: `FUN_082ab338` @ 0x082ab338
//!   (4 bytes: a bare `mov pc, lr`, 172 `bl` call sites). A no-op,
//!   because `cxa_guard_acquire` already published the initialized
//!   flag.
//!
//! # Identification
//!
//! The release stub's body is empty, so it is identified by its call
//! graph, not its code: the two functions have *exactly* the same
//! number of call sites (172 each) and every one of them is an adjacent
//! pair bracketing a constructor. The shape at 0x0803c270 is the
//! textbook function-local static:
//!
//! ```text
//!     ldr  r0, [r4, #16]        ; the guard word
//!     tst  r0, #1               ; inlined fast path: bit 0 = initialized
//!     bne  done
//!     add  r0, r4, #16
//!     bl   0x082ab31c           ; cxa_guard_acquire(&guard)
//!     cmp  r0, #0
//!     beq  done
//!     ldr  r0, =object
//!     bl   0x081f50b4           ; the constructor, returns `this`
//!     ldr  r2, =__dso_handle    ; 0x089ca09c
//!     ldr  r1, =destructor
//!     bl   0x082ab1c8           ; cxa_atexit(this, dtor, dso)
//!     add  r0, r4, #16
//!     bl   0x082ab338           ; cxa_guard_release(&guard)
//!   done:
//! ```
//!
//! `cxa_atexit` is ported in `runtime/shutdown_chain.rs`, whose runner
//! (0x082ab2b0) is what eventually calls those destructors.
//!
//! # Semantics worth pinning
//!
//! - The guard is published by *acquire*, not by release. A constructor
//!   that re-enters its own initialization therefore sees an already
//!   initialized guard and skips — the object is used half-built rather
//!   than the ctor running twice or deadlocking. Faithfully preserved.
//! - Acquire tests the whole word against zero while the inlined fast
//!   path at the call sites tests only bit 0. Any nonzero guard word
//!   with bit 0 clear (never produced by this pair) would take the slow
//!   path and still report "already initialized".
//! - There is no locking of any kind: this is the single-threaded ADS
//!   variant, and there is no `__cxa_guard_abort` in the image.

/// cxa_guard_acquire — original: `FUN_082ab31c` @ 0x082ab31c (28 bytes).
///
/// Returns 1 (and marks the guard initialized) when the caller should
/// run the initializer, 0 when someone already has.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxa_guard_acquire(guard: *mut u32) -> u32 {
    if *guard != 0 {
        return 0;
    }
    *guard = 1;
    1
}

/// cxa_guard_release — original: `FUN_082ab338` @ 0x082ab338 (4 bytes).
///
/// A no-op: [`cxa_guard_acquire`] already stored the flag. Kept as a
/// real symbol because the 172 call sites are real `bl`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxa_guard_release(_guard: *mut u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The call sites' inlined fast path: `tst guard, #1`.
    fn already_initialized(guard: u32) -> bool {
        guard & 1 != 0
    }

    #[test]
    fn the_first_caller_wins_and_publishes_the_flag() {
        let mut guard = 0u32;
        unsafe {
            assert_eq!(cxa_guard_acquire(&mut guard), 1, "first caller runs it");
            assert_eq!(guard, 1, "acquire publishes, not release");
            cxa_guard_release(&mut guard);
            assert_eq!(guard, 1, "release changes nothing");
        }
        assert!(already_initialized(guard));
    }

    #[test]
    fn later_callers_are_turned_away() {
        let mut guard = 0u32;
        unsafe {
            assert_eq!(cxa_guard_acquire(&mut guard), 1);
            for _ in 0..4 {
                assert_eq!(cxa_guard_acquire(&mut guard), 0);
                assert_eq!(guard, 1);
            }
        }
    }

    #[test]
    fn a_reentrant_initializer_sees_the_guard_already_taken() {
        // Acquire publishes before the constructor runs, so the nested
        // acquire a re-entrant ctor would perform is refused.
        let mut guard = 0u32;
        unsafe {
            assert_eq!(cxa_guard_acquire(&mut guard), 1, "outer");
            assert_eq!(cxa_guard_acquire(&mut guard), 0, "re-entry refused");
            cxa_guard_release(&mut guard);
        }
    }

    #[test]
    fn any_nonzero_guard_word_counts_as_initialized() {
        // The original compares the whole word, not just bit 0.
        for seed in [1u32, 2, 0x8000_0000, u32::MAX] {
            let mut guard = seed;
            unsafe { assert_eq!(cxa_guard_acquire(&mut guard), 0, "{seed:#x}") };
            assert_eq!(guard, seed, "a refused acquire never writes");
        }
    }

    #[test]
    fn a_full_static_init_sequence_runs_the_body_exactly_once() {
        let mut guard = 0u32;
        let mut constructions = 0;
        for _ in 0..10 {
            // The call site's inlined fast path comes first.
            if already_initialized(guard) {
                continue;
            }
            if unsafe { cxa_guard_acquire(&mut guard) } != 0 {
                constructions += 1;
                unsafe { cxa_guard_release(&mut guard) };
            }
        }
        assert_eq!(constructions, 1);
    }
}
