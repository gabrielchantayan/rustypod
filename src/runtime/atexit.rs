//! Ports of the ARM ADS 1.0.1 exit-handler machinery and the C++ static
//! init/fini table walkers:
//!
//! - atexit machinery — original: `FUN_080358b4` @ 0x080358b4 (104 bytes).
//!   The original is NOT the classic registration function; it is the ADS
//!   get-or-create accessor for the per-thread "exit block". It calls
//!   `__rt_libspace` @ 0x0803204c, loads the block pointer from
//!   libspace+0x3c, and on first use mallocs 32 bytes via
//!   `FUN_0802edac` @ 0x0802edac (malloc failure tail-calls the
//!   non-returning fatal routine @ 0x08030f44), stores the block at
//!   libspace+0x3c and initializes it:
//!     +0x00 word: 0
//!     +0x04 word: 0   (literal @ 0x0803591c is 0 in this build)
//!     +0x08 word: default exit fn = stub @ 0x080358b0 (tail-calls the
//!               fatal routine @ 0x08030f44)
//!     +0x0c byte: 0 (flag)
//!     +0x10 word: user exit fn = 0
//!     +0x14 word: 0
//!     +0x18 word: 0
//!     +0x1c word: 0 (locale-init call @ 0x08035924 skipped — its guard
//!               literal @ 0x08035920 is 0 in this build)
//!   The only consumer is the exit runner @ 0x08033720, which calls
//!   block+0x10 if non-zero (clearing the slot first), else block+0x08,
//!   and then enters the fatal routine. So the original block holds
//!   exactly ONE user exit-function slot — 32 bytes is 8 words of block,
//!   NOT 32 handler slots — and nothing in osos ever registers one.
//!
//! - `__cpp_initialise` — original: `FUN_080316cc` @ 0x080316cc (56 bytes).
//!   Walks the linker-generated C++ static-constructor table forward. Two
//!   pc-relative literal loads compute the table bounds (start
//!   0x089d4f8c, end 0x089d51d8 — 147 entries in this build); each entry
//!   is a 32-bit offset *relative to the entry's own address*, and the
//!   loop calls `entry_addr + *entry` for every slot until start == end.
//!   The port's `table`/`count` parameters map to the original's
//!   start..end pointer pair; callers pass real function pointers instead
//!   of self-relative offsets (the linker-script encoding is irrelevant
//!   to a Rust port).
//!
//! - `__cpp_finalise` — original: `FUN_080336d8` @ 0x080336d8 (60 bytes).
//!   C++ array-destruction walker: given (base, dtor, elem_size, count)
//!   it computes `base + count*elem_size` with a single `mla`, then
//!   repeatedly steps back one element and calls `dtor(elem)` until it
//!   reaches `base` — i.e. each element's destructor runs exactly once,
//!   LAST element first (reverse/LIFO order). Returns `base - 8`
//!   unconditionally (ADS `__vec_delete` convention: step the pointer
//!   back over the array-allocation header).
//!
//! Deviations from the original:
//! - The port owns the handler table directly as `static mut` instead of
//!   reaching a malloc'd block through libspace+0x3c (no heap or libspace
//!   dependency). Capacity is 8 slots, mirroring the original's 32-byte /
//!   8-word block.
//! - `atexit` implements the classic ISO C contract (0 on success, -1
//!   when the table is full); the original binary contains no
//!   registration function at all — only the accessor above.
//! - `run_exit_handlers` runs handlers LIFO, clearing each slot before
//!   calling it (mirroring the original exit runner, which clears the
//!   slot before the call so re-registration during a handler is safe).
//!   LIFO is the ISO C order and matches the reverse-order convention of
//!   `__cpp_finalise`, the only multi-callback ordering observable in the
//!   original.
//! - The fatal routine @ 0x08030f44 and the libspace/malloc calls are
//!   not modeled; overflow is reported by the -1 return instead.

/// Number of exit-handler slots. The original mallocs a 32-byte (8-word)
/// exit block on first use; the port mirrors that extent as 8 slots in a
/// static table (see module docs).
pub const EXIT_HANDLER_CAPACITY: usize = 8;

/// Registered exit handlers, filled low-to-high; only the first
/// `EXIT_HANDLER_COUNT` slots are live. Original: heap block reached via
/// libspace+0x3c; here a zero-initialized `static mut` (see module docs).
static mut EXIT_HANDLERS: [Option<extern "C" fn()>; EXIT_HANDLER_CAPACITY] =
    [None; EXIT_HANDLER_CAPACITY];

/// Number of live slots in `EXIT_HANDLERS`.
static mut EXIT_HANDLER_COUNT: usize = 0;

/// atexit — original accessor: `FUN_080358b4` @ 0x080358b4 (104 bytes).
///
/// Registers `handler` to run at exit. Returns 0 on success, -1 when the
/// table is full (the original would die in the fatal routine @
/// 0x08030f44 on allocation failure instead).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn atexit(handler: extern "C" fn()) -> i32 {
    let count = *core::ptr::addr_of!(EXIT_HANDLER_COUNT);
    if count >= EXIT_HANDLER_CAPACITY {
        return -1;
    }
    (*core::ptr::addr_of_mut!(EXIT_HANDLERS))[count] = Some(handler);
    *core::ptr::addr_of_mut!(EXIT_HANDLER_COUNT) = count + 1;
    0
}

/// Runs all registered exit handlers in LIFO order (last registered,
/// first run). Each slot is cleared before its handler is called, so a
/// handler that registers a new handler cannot cause a re-run of already
/// fired handlers. Companion of the exit runner @ 0x08033720.
pub unsafe fn run_exit_handlers() {
    loop {
        let count = *core::ptr::addr_of!(EXIT_HANDLER_COUNT);
        if count == 0 {
            return;
        }
        let top = count - 1;
        *core::ptr::addr_of_mut!(EXIT_HANDLER_COUNT) = top;
        if let Some(handler) = (*core::ptr::addr_of_mut!(EXIT_HANDLERS))[top].take() {
            handler();
        }
    }
}

/// __cpp_initialise — original: `FUN_080316cc` @ 0x080316cc (56 bytes).
///
/// Calls each of the `count` static constructors in `table`, first entry
/// first, exactly once. In the original the table is a linker-generated
/// region of self-relative offsets bounded by two pc-relative addresses;
/// here the caller passes a plain function-pointer array (see module
/// docs).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe fn __cpp_initialise(table: *const extern "C" fn(), count: usize) {
    for i in 0..count {
        (*table.add(i))();
    }
}

/// __cpp_finalise — original: `FUN_080336d8` @ 0x080336d8 (60 bytes).
///
/// Calls `dtor` on each element of the `count`-element array at `base`
/// with element stride `elem_size`, LAST element first, exactly once per
/// element. Returns `base - 8` unconditionally, matching the original
/// (ADS `__vec_delete` array-header convention).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe fn __cpp_finalise(
    base: *mut u8,
    dtor: extern "C" fn(*mut u8),
    elem_size: usize,
    count: usize,
) -> *mut u8 {
    if count != 0 {
        // Original: one `mla` computes base + count*elem_size, then the
        // loop pre-decrements by elem_size and calls dtor until base.
        let mut elem = base.add(count.wrapping_mul(elem_size));
        loop {
            elem = elem.sub(elem_size);
            dtor(elem);
            if elem == base {
                break;
            }
        }
    }
    base.sub(8)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that touch the shared statics.
    static LOCK: Mutex<()> = Mutex::new(());

    /// Order in which handlers/dtors fired (handler ids or element
    /// indices), drained by each test.
    static CALL_LOG: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    macro_rules! handler {
        ($name:ident, $id:expr) => {
            extern "C" fn $name() {
                CALL_LOG.lock().unwrap().push($id);
            }
        };
    }

    handler!(handler_0, 0);
    handler!(handler_1, 1);
    handler!(handler_2, 2);
    handler!(handler_3, 3);
    handler!(handler_4, 4);
    handler!(handler_5, 5);
    handler!(handler_6, 6);
    handler!(handler_7, 7);
    handler!(handler_overflow, 99);

    /// Single test for all atexit state: the statics are process-global,
    /// so interleaving with other test threads must be impossible.
    #[test]
    fn atexit_lifo_and_capacity() {
        let _guard = LOCK.lock().unwrap();
        unsafe {
            // Register N handlers: all accepted.
            let handlers = [
                handler_0, handler_1, handler_2, handler_3, handler_4, handler_5, handler_6,
                handler_7,
            ];
            for (i, h) in handlers.iter().enumerate() {
                assert_eq!(atexit(*h), 0, "registration {i} must succeed");
            }
            // Capacity: the table now holds EXIT_HANDLER_CAPACITY (8)
            // handlers; the next registration must fail with -1.
            assert_eq!(atexit(handler_overflow), -1, "9th registration must fail");
            assert_eq!(
                *core::ptr::addr_of!(EXIT_HANDLER_COUNT),
                EXIT_HANDLER_CAPACITY
            );

            // LIFO run: last registered runs first, each exactly once,
            // and the overflow handler never runs.
            run_exit_handlers();
            assert_eq!(
                CALL_LOG.lock().unwrap().as_slice(),
                &[7usize, 6, 5, 4, 3, 2, 1, 0][..],
                "handlers must run LIFO"
            );
            assert_eq!(*core::ptr::addr_of!(EXIT_HANDLER_COUNT), 0);

            // Running with an empty table is a no-op.
            run_exit_handlers();
            assert!(CALL_LOG.lock().unwrap().len() == 8);
        }
    }

    /// A handler registering another handler mid-run: the slot is cleared
    /// before the call (as in the original exit runner), so the new
    /// handler is picked up by the same run, after everything already
    /// pending.
    #[test]
    fn reregistration_during_run() {
        let _guard = LOCK.lock().unwrap();
        CALL_LOG.lock().unwrap().clear();
        extern "C" fn late() {
            CALL_LOG.lock().unwrap().push(20);
        }
        extern "C" fn re_registers() {
            CALL_LOG.lock().unwrap().push(10);
            unsafe {
                assert_eq!(atexit(late), 0);
            }
        }
        unsafe {
            assert_eq!(atexit(handler_0), 0);
            assert_eq!(atexit(re_registers), 0);
            run_exit_handlers();
            // re_registers runs first (LIFO), then its freshly registered
            // `late`, then handler_0.
            assert_eq!(CALL_LOG.lock().unwrap().as_slice(), &[10usize, 20, 0][..]);
            assert_eq!(*core::ptr::addr_of!(EXIT_HANDLER_COUNT), 0);
        }
    }

    extern "C" fn ctor_0() {
        CALL_LOG.lock().unwrap().push(0);
    }
    extern "C" fn ctor_1() {
        CALL_LOG.lock().unwrap().push(1);
    }
    extern "C" fn ctor_2() {
        CALL_LOG.lock().unwrap().push(2);
    }

    #[test]
    fn cpp_initialise_calls_each_ctor_once_in_order() {
        let _guard = LOCK.lock().unwrap();
        CALL_LOG.lock().unwrap().clear();
        static CTORS: [extern "C" fn(); 3] = [ctor_0, ctor_1, ctor_2];
        unsafe {
            __cpp_initialise(CTORS.as_ptr(), CTORS.len());
            assert_eq!(CALL_LOG.lock().unwrap().as_slice(), &[0usize, 1, 2][..]);

            // Zero count: no calls, no reads past the table.
            CALL_LOG.lock().unwrap().clear();
            __cpp_initialise(CTORS.as_ptr(), 0);
            assert!(CALL_LOG.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn cpp_finalise_walks_elements_in_reverse_exactly_once() {
        let _guard = LOCK.lock().unwrap();
        CALL_LOG.lock().unwrap().clear();

        const ELEM_SIZE: usize = 4;
        const COUNT: usize = 4;
        let mut array = [0xAAu8; ELEM_SIZE * COUNT];

        extern "C" fn dtor(elem: *mut u8) {
            // Record the raw element pointer; order/index checked below.
            DTOR_HITS.lock().unwrap().push(elem as usize);
        }
        static DTOR_HITS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
        DTOR_HITS.lock().unwrap().clear();

        unsafe {
            let base = array.as_mut_ptr();
            let ret = __cpp_finalise(base, dtor, ELEM_SIZE, COUNT);
            // Return value: base - 8, unconditionally (original behavior).
            assert_eq!(ret, base.sub(8));

            let hits = DTOR_HITS.lock().unwrap();
            assert_eq!(hits.len(), COUNT, "each element visited exactly once");
            for (i, &hit) in hits.iter().enumerate() {
                // Reverse order: last element first.
                let expected_elem = COUNT - 1 - i;
                assert_eq!(hit, base.add(expected_elem * ELEM_SIZE) as usize);
            }
        }
    }

    #[test]
    fn cpp_finalise_zero_count_calls_nothing_but_still_returns_base_minus_8() {
        let _guard = LOCK.lock().unwrap();
        let mut array = [0u8; 16];
        extern "C" fn dtor(_elem: *mut u8) {
            panic!("dtor must not be called when count == 0");
        }
        unsafe {
            let base = array.as_mut_ptr();
            let ret = __cpp_finalise(base, dtor, 4, 0);
            assert_eq!(ret, base.sub(8));
        }
    }
}
