//! Object-header flag predicates and the singleton flag-word counter
//! accessor ported from retailOS.

/// object_low_flags_clear — original: `FUN_0808539c` @ `0x0808539c`
/// (20 bytes; source: `ipod-decomp/decomp/c/005/0808539c_FUN_0808539c.c`).
///
/// Loads the 32-bit flag word at offset `+0x04` of an aligned object and
/// returns 1 exactly when its low three bits are all clear; it returns 0
/// otherwise. The retail sequence is `ldr; tst #7; moveq #1; movne #0; bx lr`.
/// The object type and meanings of the individual bits are still unknown, so
/// the name describes the verified field-level behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_low_flags_clear(object: *const u8) -> u32 {
    u32::from((object.add(4).cast::<u32>().read_volatile() & 0x7) == 0)
}

/// object_value_set_flags_clear — original: `FUN_08085344` @ `0x08085344`
/// (16 bytes; source: `ipod-decomp/decomp/c/005/08085344_FUN_08085344.c`).
///
/// Initializes the two-word object header: stores `value` into the 32-bit
/// word at offset `+0x00` and clears the whole 32-bit flag word at offset
/// `+0x04` (the same flag word object_low_flags_clear @ 0x0808539c tests).
/// The retail sequence is `str r1,[r0]; mov r1,#0; str r1,[r0,#4]; bx lr`.
/// All three call sites (0x081b0594, 0x081b05c4, 0x081b06f4) apply it to
/// the sub-header at object+0xb8 with a value loaded from a data cursor,
/// so the header reads as { position-or-pointer, flags }; the concrete
/// object type is still unidentified, so the name describes the verified
/// field-level behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_value_set_flags_clear(object: *mut u8, value: u32) {
    object.cast::<u32>().write_volatile(value);
    object.add(4).cast::<u32>().write_volatile(0);
}

/// Dispatcher op for the acquire half of the bracket around
/// [`object_flags_fetch_increment`] (`mov r0, #0x9` @ 0x08085364).
const LOCK_DISPATCH_ACQUIRE: u32 = 9;
/// Dispatcher op for the release half (`mov r0, #0xa` @ 0x08085388).
const LOCK_DISPATCH_RELEASE: u32 = 10;
/// Lock selected for the bracket (`mov r1, #0x2`; the third and fourth
/// dispatcher arguments are always zero here).
const SINGLETON_LOCK: u32 = 2;

/// Injection point for `FUN_08043b94`, the retailOS lock dispatcher: the
/// `bl` @ 0x08085368 passes (op, lock, 0, 0) before the increment and the
/// `bl` @ 0x0808538c passes the release op after it. Op 9/10 pairs
/// bracket critical sections throughout retailOS (59 `bl 0x08043b94`
/// sites); the dispatcher's own negative-argument path performs a
/// timeout-queue wait, confirming the acquire/release roles.
pub type LockDispatch = unsafe extern "C" fn(u32, u32, u32, u32);

/// Spins forever: [`object_flags_fetch_increment`] must not run before
/// target integration installs the retailOS dispatcher.
unsafe extern "C" fn missing_lock_dispatch(
    _op: u32,
    _lock: u32,
    _reserved_a: u32,
    _reserved_b: u32,
) {
    loop {
        core::hint::spin_loop();
    }
}

/// RetailOS dependency of [`object_flags_fetch_increment`]. Target
/// integration must install the real `FUN_08043b94`; focused host tests
/// replace it with a recording seam.
pub static mut OBJECT_FLAGS_FETCH_INCREMENT_LOCK: LockDispatch = missing_lock_dispatch;

#[inline(always)]
unsafe fn lock_dispatch() -> LockDispatch {
    core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_FLAGS_FETCH_INCREMENT_LOCK))
}

/// Load address of the fixed retailOS singleton whose +0x04 word
/// [`object_flags_fetch_increment`] increments: the literal pool word
/// @ 0x08085398 holds 0x08a0e9e0, and the object is shared with the
/// lock-dispatch machinery (FUN_08075914 lazily points its +0x00 word at
/// the embedded vtable @ 0x08a0e9ec; FUN_080439e0 / FUN_08043e04 call
/// through its vtable slots +0x14 / +0x0c).
#[cfg(target_os = "none")]
const SINGLETON_OBJECT: *mut u32 = 0x08a0_e9e0 as *mut u32;

/// Host stand-in for the firmware singleton: the +0x00 vtable word is
/// unused by this function; the +0x04 word is the counter under test.
#[cfg(not(target_os = "none"))]
static mut HOST_SINGLETON_OBJECT: [u32; 2] = [0; 2];

/// The aligned 32-bit word at +0x04 of the singleton.
#[inline(always)]
unsafe fn singleton_flags_word() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        SINGLETON_OBJECT.add(1)
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_SINGLETON_OBJECT).cast::<u32>().add(1)
    }
}

/// object_flags_fetch_increment — original: `FUN_08085354` @ `0x08085354`
/// (68 bytes: 64 of code plus the 4-byte singleton pointer literal
/// @ 0x08085398; source:
/// `ipod-decomp/decomp/c/005/08085354_FUN_08085354.c`).
///
/// Fetch-and-increment of the fixed singleton's +0x04 word — the same
/// header offset object_low_flags_clear @ 0x0808539c tests and
/// object_value_set_flags_clear @ 0x08085344 clears on their
/// caller-passed objects — under the retailOS lock dispatcher
/// `FUN_08043b94`: acquire (9, 2, 0, 0), read the word, store the value
/// plus one, release (10, 2, 0, 0), and return the pre-increment value.
/// The retail sequence is `stmdb sp!,{r4,lr}; bl dispatch(9,2,0,0);
/// ldr r4,[obj,#4]; add r1,r4,#1; str r1,[obj,#4]; bl dispatch(10,2,0,0);
/// mov r0,r4; ldmia sp!,{r4,pc}`. The word's role (plain counter versus
/// sequence number) is unverified, so the name claims only the observed
/// fetch-and-increment.
///
/// Deviations: the unported dispatcher rides the
/// [`OBJECT_FLAGS_FETCH_INCREMENT_LOCK`] seam (house pattern — see
/// app/node_list.rs's NODE_LIST_ENQUEUE_OPS) instead of a direct `bl`,
/// and host builds substitute test storage for the firmware singleton
/// @ 0x08a0e9e0.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_flags_fetch_increment() -> u32 {
    let dispatch = lock_dispatch();
    dispatch(LOCK_DISPATCH_ACQUIRE, SINGLETON_LOCK, 0, 0);
    let word = singleton_flags_word();
    let previous = word.read_volatile();
    word.write_volatile(previous.wrapping_add(1));
    dispatch(LOCK_DISPATCH_RELEASE, SINGLETON_LOCK, 0, 0);
    previous
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An aligned stand-in for the unidentified retail object header.
    #[repr(C, align(4))]
    struct ObjectHeader {
        bytes: [u8; 8],
    }

    fn invoke(flags: u32) -> u32 {
        let mut object = ObjectHeader { bytes: [0; 8] };
        object.bytes[4..8].copy_from_slice(&flags.to_le_bytes());
        unsafe { object_low_flags_clear(object.bytes.as_ptr()) }
    }

    fn invoke_init(initial: [u8; 8], value: u32) -> [u8; 8] {
        let mut object = ObjectHeader { bytes: initial };
        unsafe { object_value_set_flags_clear(object.bytes.as_mut_ptr(), value) };
        object.bytes
    }

    fn reference(flags: u32) -> u32 {
        u32::from(flags & 0x7 == 0)
    }

    #[test]
    fn low_flag_combinations_match_reference() {
        for low_flags in 0..8 {
            assert_eq!(invoke(low_flags), reference(low_flags));
        }
    }

    #[test]
    fn higher_bits_do_not_affect_low_flag_predicate() {
        for flags in [0x8, 0x10, 0x8000_0000, 0xffff_fff8, 0xa5a5_a5a8] {
            assert_eq!(invoke(flags), 1, "flags={flags:#010x}");
        }
    }

    #[test]
    fn any_set_low_flag_makes_result_false() {
        for high_bits in [0, 0x8, 0x1234_5600, 0xffff_fff8] {
            for low_flags in 1..8 {
                let flags = high_bits | low_flags;
                assert_eq!(invoke(flags), 0, "flags={flags:#010x}");
            }
        }
    }

    #[test]
    fn init_stores_value_and_clears_flag_word() {
        for value in [0, 1, 0x0800_0000, 0xdead_beef, 0xffff_ffff] {
            let object = invoke_init([0xaa; 8], value);
            assert_eq!(&object[0..4], &value.to_le_bytes(), "value={value:#010x}");
            assert_eq!(&object[4..8], &[0; 4], "value={value:#010x}");
        }
    }

    #[test]
    fn init_clears_every_flag_bit_pattern() {
        for flags in [0x7u32, 0xffff_ffff, 0xa5a5_a5a5, 0x8000_0000, 0x1234_5678] {
            let mut initial = [0xcc; 8];
            initial[4..8].copy_from_slice(&flags.to_le_bytes());
            let object = invoke_init(initial, 0x1111_2222);
            assert_eq!(&object[4..8], &[0; 4], "flags={flags:#010x}");
        }
    }

    #[test]
    fn init_leaves_low_flags_clear_predicate_true() {
        let mut object = ObjectHeader { bytes: [0xff; 8] };
        unsafe { object_value_set_flags_clear(object.bytes.as_mut_ptr(), 42) };
        assert_eq!(unsafe { object_low_flags_clear(object.bytes.as_ptr()) }, 1);
    }

    extern crate std;
    use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};

    /// Serializes the tests that swap the lock-dispatch seam and the host
    /// singleton storage.
    static FETCH_INCREMENT_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    /// One recorded dispatcher invocation: the four arguments plus the
    /// singleton +0x04 word observed at call time, which pins the acquire
    /// before the store and the release after it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LockCall {
        op: u32,
        lock: u32,
        reserved_a: u32,
        reserved_b: u32,
        word_at_call: u32,
    }

    const NO_LOCK_CALL: LockCall =
        LockCall { op: 0, lock: 0, reserved_a: 0, reserved_b: 0, word_at_call: 0 };

    static mut LOCK_CALLS: [LockCall; 8] = [NO_LOCK_CALL; 8];
    static mut LOCK_CALL_COUNT: usize = 0;

    unsafe extern "C" fn recording_lock_dispatch(
        op: u32,
        lock: u32,
        reserved_a: u32,
        reserved_b: u32,
    ) {
        let word_at_call = singleton_flags_word().read_volatile();
        let count = LOCK_CALL_COUNT;
        assert!(count < 8, "lock dispatcher called more than 8 times");
        LOCK_CALLS[count] = LockCall { op, lock, reserved_a, reserved_b, word_at_call };
        LOCK_CALL_COUNT = count + 1;
    }

    /// Installs the recording seam, seeds the host singleton's +0x04 word,
    /// and returns the guard serializing the swap.
    fn install_recording_lock(initial: u32) -> StdMutexGuard<'static, ()> {
        let guard = FETCH_INCREMENT_TEST_LOCK.lock().unwrap();
        unsafe {
            singleton_flags_word().write_volatile(initial);
            LOCK_CALL_COUNT = 0;
            OBJECT_FLAGS_FETCH_INCREMENT_LOCK = recording_lock_dispatch;
        }
        guard
    }

    fn uninstall_recording_lock() {
        unsafe { OBJECT_FLAGS_FETCH_INCREMENT_LOCK = missing_lock_dispatch };
    }

    fn recorded_calls() -> (usize, [LockCall; 8]) {
        unsafe { (LOCK_CALL_COUNT, LOCK_CALLS) }
    }

    #[test]
    fn fetch_increment_returns_previous_and_stores_next() {
        for initial in [0u32, 1, 7, 0xffff_fffe, 0xdead_beef, 0xa5a5_a5a5] {
            let _guard = install_recording_lock(initial);
            let returned = unsafe { object_flags_fetch_increment() };
            assert_eq!(returned, initial, "initial={initial:#010x}");
            assert_eq!(
                unsafe { singleton_flags_word().read_volatile() },
                initial.wrapping_add(1),
                "initial={initial:#010x}"
            );
            uninstall_recording_lock();
        }
    }

    #[test]
    fn fetch_increment_wraps_at_u32_max() {
        let _guard = install_recording_lock(0xffff_ffff);
        let returned = unsafe { object_flags_fetch_increment() };
        assert_eq!(returned, 0xffff_ffff);
        // ARM `add r1, r4, #1` wraps modulo 2^32; no overflow trap.
        assert_eq!(unsafe { singleton_flags_word().read_volatile() }, 0);
        uninstall_recording_lock();
    }

    #[test]
    fn consecutive_calls_return_strictly_increasing_values() {
        let _guard = install_recording_lock(41);
        for expected in 41..44 {
            assert_eq!(unsafe { object_flags_fetch_increment() }, expected);
        }
        assert_eq!(unsafe { singleton_flags_word().read_volatile() }, 44);
        uninstall_recording_lock();
    }

    #[test]
    fn increment_is_bracketed_by_acquire_and_release() {
        let _guard = install_recording_lock(0x1234_5678);
        let returned = unsafe { object_flags_fetch_increment() };
        assert_eq!(returned, 0x1234_5678);
        let (count, calls) = recorded_calls();
        assert_eq!(count, 2, "exactly one acquire and one release");
        assert_eq!(
            calls[0],
            LockCall { op: 9, lock: 2, reserved_a: 0, reserved_b: 0, word_at_call: 0x1234_5678 },
            "acquire (9,2,0,0) precedes the store"
        );
        assert_eq!(
            calls[1],
            LockCall { op: 10, lock: 2, reserved_a: 0, reserved_b: 0, word_at_call: 0x1234_5679 },
            "release (10,2,0,0) follows the store"
        );
        uninstall_recording_lock();
    }

    #[test]
    fn whole_word_increments_through_set_low_flag_bits() {
        // The add is a plain whole-word increment: it neither preserves
        // nor specially treats the low three bits the neighbor predicate
        // tests.
        for (initial, expected) in [(0x7u32, 0x8u32), (0xffff_fff7, 0xffff_fff8), (0xff, 0x100)] {
            let _guard = install_recording_lock(initial);
            assert_eq!(unsafe { object_flags_fetch_increment() }, initial);
            assert_eq!(unsafe { singleton_flags_word().read_volatile() }, expected);
            uninstall_recording_lock();
        }
    }
}
