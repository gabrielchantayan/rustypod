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
//!
//! # inner_result_count — original: `FUN_0813b7d0` @ 0x0813b7d0 (8 bytes)
//!
//! 1 `bl` call site: the query runner `FUN_080feb68` @ 0x080febc8, two
//! instructions after its `inner_set_state_4` call. A two-instruction
//! forwarding wrapper — the read-side sibling of `inner_set_state_4`:
//!
//! ```text
//! ldr r0, [r0, #0x40]   @ inner = this->inner
//! b   0x080542a0        @ tail: materialize-and-count(inner)
//! ```
//!
//! The tail target `FUN_080542a0` @ 0x080542a0 (20 bytes, 3 `bl` call
//! sites) calls the lazy materializer `FUN_08086694` @ 0x08086694 (480
//! bytes: when the cached result-array pointer at inner+0xeec is NULL it
//! builds the array under a mutex, caching the array at +0xeec, an aux
//! pointer at +0xef0 and the result count at +0xef4 — a no-op otherwise)
//! and returns the count word at inner+0xef4. The sole caller uses the
//! result as the loop bound over the per-index record fetch
//! `FUN_0813b898` after running query 0x32 — the number of records the
//! query produced.
//!
//! Deviation: the materializer is unported firmware (it allocates,
//! walks a record table and locks a mutex through nine further
//! callees), so the whole tail target sits behind the
//! [`INNER_MATERIALIZE_COUNT`] dispatch slot (the app/class_registry.rs
//! pattern). The default stub is the materializer's no-op path: it
//! reads the cached count word at +0xef4 without materializing — exact
//! once a query has populated the cache, which is the only state the
//! sole caller ever observes (it runs query 0x32 before asking).

/// Byte offset of the inner-object pointer inside the query object.
const INNER: usize = 0x40;

/// Byte offset of the state/mode word inside the inner object.
const STATE: usize = 0xe38;

/// The state value this wrapper always stores.
const STATE_4: u32 = 4;

/// Byte offset of the result-count word inside the inner object
/// (written by the lazy materializer @ 0x08086694, read back by the
/// tail target @ 0x080542a0).
const RESULT_COUNT: usize = 0xef4;

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

/// Default [`INNER_MATERIALIZE_COUNT`] stub: the no-op path of the
/// unported materialize-and-count tail target `FUN_080542a0` @
/// 0x080542a0 — reads the cached result-count word at inner+0xef4
/// without running the unported 480-byte materializer @ 0x08086694
/// (exact once the query has populated the cache; see the module
/// header).
unsafe extern "C" fn materialize_count_stub(inner: *mut u8) -> u32 {
    (inner.add(RESULT_COUNT) as *const u32).read()
}

/// Indirect dispatch for the unported materialize-and-count tail target
/// @ 0x080542a0 (the app/class_registry.rs pattern). Host tests install
/// a recording mock; the real port replaces the default stub when the
/// materializer @ 0x08086694 is ported.
pub static mut INNER_MATERIALIZE_COUNT: unsafe extern "C" fn(inner: *mut u8) -> u32 =
    materialize_count_stub;

/// inner_result_count — original: `FUN_0813b7d0` @ 0x0813b7d0 (8 bytes).
///
/// Loads the inner object from `object + 0x40` and tail-branches to the
/// materialize-and-count getter, returning the query's result count
/// (the word at inner+0xef4 after the lazy materializer has run).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inner_result_count(object: *mut u8) -> u32 {
    let inner = (object.add(INNER) as *const *mut u8).read();
    // Volatile slot read — the class_registry.rs `ops!` rationale: the
    // slot is meant to be swapped at runtime, and a build in which
    // nothing swaps it must not constant-fold the default in.
    let materialize =
        core::ptr::read_volatile(core::ptr::addr_of!(INNER_MATERIALIZE_COUNT));
    materialize(inner)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    const INNER_LEN: usize = RESULT_COUNT + 4;
    // The +0x40 slot is pointer-wide: 4 bytes on the target, 8 on a
    // 64-bit test host.
    const OUTER_LEN: usize = INNER + core::mem::size_of::<*mut u8>();
    const SENTINEL: u8 = 0xa5;

    /// Serializes the tests that swap `INNER_MATERIALIZE_COUNT` (the
    /// wstr_casecmp.rs `FOLD_TEST_LOCK` precedent).
    static SLOT_TEST_LOCK: Mutex<()> = Mutex::new(());

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

    // ---- inner_result_count -------------------------------------------

    static mut MOCK_SEEN: *mut u8 = core::ptr::null_mut();
    static mut MOCK_CALLS: u32 = 0;
    const MOCK_COUNT: u32 = 0x5a5a_0007;

    unsafe extern "C" fn recording_materialize(inner: *mut u8) -> u32 {
        MOCK_SEEN = inner;
        MOCK_CALLS += 1;
        MOCK_COUNT
    }

    /// Restores the default stub on drop, even when a test panics.
    struct SlotGuard;
    impl Drop for SlotGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(INNER_MATERIALIZE_COUNT)
                    .write_volatile(materialize_count_stub)
            };
        }
    }

    #[test]
    fn forwards_the_inner_pointer_and_returns_the_count() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        fixture.link();
        let inner_base = fixture.inner.as_mut_ptr();
        unsafe {
            MOCK_SEEN = core::ptr::null_mut();
            MOCK_CALLS = 0;
            core::ptr::addr_of_mut!(INNER_MATERIALIZE_COUNT)
                .write_volatile(recording_materialize);

            let count = inner_result_count(fixture.outer.as_mut_ptr());

            assert_eq!(count, MOCK_COUNT);
            assert_eq!(MOCK_CALLS, 1, "exactly one tail call");
            assert_eq!(MOCK_SEEN, inner_base, "the +0x40 slot value is forwarded");
        }
    }

    #[test]
    fn default_stub_reads_the_cached_count_word() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut fixture = Fixture::new();
        fixture.link();
        // Preload the count the materializer would have cached.
        fixture.inner[RESULT_COUNT..RESULT_COUNT + 4]
            .copy_from_slice(&0x2au32.to_le_bytes());
        let inner_before = fixture.inner;

        let count = unsafe { inner_result_count(fixture.outer.as_mut_ptr()) };

        assert_eq!(count, 0x2a);
        // The no-op path reads only: every inner byte is untouched.
        assert_eq!(fixture.inner, inner_before);
        // And the outer object (including the +0x40 slot) is untouched.
        let mut outer_expect = [SENTINEL; OUTER_LEN];
        let ptr = fixture.inner.as_mut_ptr();
        unsafe {
            (outer_expect.as_mut_ptr().add(INNER) as *mut *mut u8).write(ptr);
        }
        assert_eq!(fixture.outer, outer_expect);
    }

    #[test]
    fn default_stub_returns_a_zero_count_for_a_fresh_object() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let mut fixture = Fixture::new();
        fixture.link();
        fixture.inner = [0; INNER_LEN];
        let count = unsafe { inner_result_count(fixture.outer.as_mut_ptr()) };
        assert_eq!(count, 0);
    }
}
