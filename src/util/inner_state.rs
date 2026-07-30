//! inner_set_state_4 — original: `FUN_0813b7c4` @ 0x0813b7c4 (12 bytes;
//! 1 `bl` call site: the query runner `FUN_080feb68` @ 0x080feba4).
//!
//! A three-instruction forwarding wrapper:
//!
//! ```text
//! ldr r0, [r0, #0x40]   @ inner = this->inner
//! mov r1, #0x4
//! b   0x08067ca4        @ tail: inner->+0xe38 = 4  (str r1,[r0,#0xe38]; bx lr)
//! ```
//!
//! `this` is the 72-byte stack-local query object built by the
//! constructor `FUN_0813e474` and torn down by `FUN_0813e5c4`; its word
//! at +0x40 points at a much larger inner object (fields observed out to
//! +0xf68, a count/limit word). The word at inner+0xe38 is a small
//! state/mode word: other code stores 1 (`FUN_08053f9c` @ 0x08053fdc,
//! alongside the +0xef9/+0xefa flag bytes), 3 (0x08054038) and 5
//! (0x08061020) into it, and the reader @ 0x0808cf4c compares it against
//! 1 to pick a result code. The sole caller stores 4 right before
//! running query 0x32 through the sibling wrappers `FUN_0813bd10`
//! (inner forward with constant 0) and `FUN_0813d064`. The exact enum is
//! not identified; the function is ported on observable behavior.
//!
//! Sits immediately after the util/berec.rs big-endian record reader
//! cluster @ 0x0813b714..0x0813b7b0 but is NOT one of them: no record
//! handle, no big-endian decode — an object-state setter.
//!
//! Deviation: the original tail-branches to the 8-byte setter
//! `FUN_08067ca4` @ 0x08067ca4 (`str r1,[r0,#0xe38]; bx lr`); the port
//! inlines that store (it is the callee's whole body), so the ARM build
//! is `ldr/mov/str/bx` instead of `ldr/mov/b`. Byte-offset addressing on
//! a `*mut u8` (the util/state_flags.rs precedent) keeps the layout
//! exact on a 64-bit test host.

/// Byte offset of the inner-object pointer inside the query object.
const INNER: usize = 0x40;

/// Byte offset of the state/mode word inside the inner object.
const STATE: usize = 0xe38;

/// The state value this wrapper always stores.
const STATE_4: u32 = 4;

/// inner_set_state_4 — original: `FUN_0813b7c4` @ 0x0813b7c4 (12 bytes).
///
/// Loads the inner object from `object + 0x40` and stores 4 into its
/// state word at +0xe38. Returns nothing (the original is a tail branch
/// to a void setter; the sole caller discards r0).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inner_set_state_4(object: *mut u8) {
    let inner = (object.add(INNER) as *const *mut u8).read();
    (inner.add(STATE) as *mut u32).write(STATE_4);
}

#[cfg(test)]
mod tests {
    use super::*;

    const INNER_LEN: usize = STATE + 4;
    // The +0x40 slot is pointer-wide: 4 bytes on the target, 8 on a
    // 64-bit test host.
    const OUTER_LEN: usize = INNER + core::mem::size_of::<*mut u8>();
    const SENTINEL: u8 = 0xa5;

    /// A stand-in outer object whose +0x40 slot points at a stand-in
    /// inner object, both filled with sentinel bytes.
    struct Fixture {
        outer: [u8; OUTER_LEN],
        inner: [u8; INNER_LEN],
    }

    impl Fixture {
        fn new() -> Self {
            Fixture { outer: [SENTINEL; OUTER_LEN], inner: [SENTINEL; INNER_LEN] }
        }
        /// Writes a genuine host pointer into the +0x40 slot — on the
        /// 32-bit target this is exactly the original's word store.
        fn link(&mut self) {
            let ptr = self.inner.as_mut_ptr();
            unsafe { (self.outer.as_mut_ptr().add(INNER) as *mut *mut u8).write(ptr) };
        }
        fn call(&mut self) {
            unsafe { inner_set_state_4(self.outer.as_mut_ptr()) }
        }
        fn state(&self) -> u32 {
            u32::from_le_bytes(self.inner[STATE..STATE + 4].try_into().unwrap())
        }
    }

    #[test]
    fn stores_4_into_the_inner_state_word() {
        let mut fixture = Fixture::new();
        fixture.link();
        fixture.call();
        assert_eq!(fixture.state(), STATE_4);
    }

    #[test]
    fn touches_only_the_two_words_it_owns() {
        let mut fixture = Fixture::new();
        let inner_before = fixture.inner;
        fixture.link();
        fixture.call();

        // Outer object: only the +0x40 slot may differ (it does not).
        assert_eq!(&fixture.outer[..INNER], &[SENTINEL; INNER]);

        // Inner object: only the state word at +0xe38 changed.
        for offset in 0..INNER_LEN {
            let expect = if (STATE..STATE + 4).contains(&offset) {
                [4u8, 0, 0, 0][offset - STATE]
            } else {
                inner_before[offset]
            };
            assert_eq!(fixture.inner[offset], expect, "inner +{offset:#x}");
        }
    }

    #[test]
    fn overwrites_a_previous_state_value() {
        let mut fixture = Fixture::new();
        fixture.link();
        // Preload state 1, the value the 0x08053fdc writer stores.
        fixture.inner[STATE..STATE + 4].copy_from_slice(&1u32.to_le_bytes());
        fixture.call();
        assert_eq!(fixture.state(), STATE_4);
    }

    #[test]
    fn is_idempotent() {
        let mut fixture = Fixture::new();
        fixture.link();
        fixture.call();
        fixture.call();
        assert_eq!(fixture.state(), STATE_4);
    }
}
