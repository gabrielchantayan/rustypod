//! The two-word-header derived-class constructor the application layer
//! runs to bring up its 200-byte service objects (90 `bl` call sites).
//!
//! The scouted notes for this address originally described a three-way
//! pointer clamp — that clamp lives at 0x083d5eb4 / 0x083d5ed8 and is
//! already ported as `util::three_pointer_select`. What actually sits
//! at 0x08124a38 is a constructor:
//!
//! ```text
//! stmdb sp!, {r4, lr}
//! stmia r0!, {r1, r2}   ; this[0] = arg0, this[1] = arg1; cursor = this+8
//! add   r0, r0, #0x4    ; skip the flag word at +8; base subobject at +12
//! bl    0x0810ebbc      ; base-class ctor, returns its argument
//! sub   r0, r0, #0xc    ; back to `this`
//! mov   r1, #0
//! str   r1, [r0, #0xc4] ; clear trailing word
//! strb  r1, [r0, #0x8]  ; clear flag byte
//! ldmia sp!, {r4, pc}   ; return `this`
//! ```
//!
//! Callers allocate exactly 200 bytes (0xc8) per object (e.g.
//! `FUN_082aadd4(200)` at the 0x081b8c20 call cluster), matching the
//! layout: two header words at +0/+4, a flag byte at +8, the base-class
//! subobject at +12 (the 0x0810ebbc ctor stores a vtable, chains to
//! 0x0813eee0 and clears fields through base+0xb4 = this+0xc0), and the
//! derived trailing word at +0xc4. The class itself is unidentified —
//! the name is structural (see the names.yaml notes).

/// Host-test dispatch for the still-unported `FUN_082b498c` array helper.
/// Its eleven ARM word arguments are represented explicitly so callers cannot
/// accidentally change the stack-argument order.
#[derive(Clone, Copy)]
pub struct PairHeaderElementArrayOps {
    /// Resets or initializes an element array and returns the helper's raw
    /// pointer result. `FUN_082ab398` deliberately discards that result.
    pub reset: unsafe extern "C" fn(
        this: *mut u32,
        field_count: u32,
        field_size: u32,
        allocation_header_bytes: u32,
        initializer_argument: u32,
        element_initializer: u32,
        initializer_context: u32,
        allocator_callback: u32,
        allocator_context: u32,
        allocation_flags: u32,
        zero_initialize: u32,
    ) -> *mut u32,
}

/// Default stand-in for the still-unported `FUN_082b498c`. It preserves the
/// helper's pointer-return ABI but performs no initialization.
unsafe extern "C" fn missing_reset_element_array(
    this: *mut u32,
    _field_count: u32,
    _field_size: u32,
    _allocation_header_bytes: u32,
    _initializer_argument: u32,
    _element_initializer: u32,
    _initializer_context: u32,
    _allocator_callback: u32,
    _allocator_context: u32,
    _allocation_flags: u32,
    _zero_initialize: u32,
) -> *mut u32 {
    this
}

/// The active `FUN_082b498c` host-test seam. Only its exact eleven-word ABI
/// is modeled here; the helper's allocation and initialization algorithm is
/// intentionally not ported.
pub static mut PAIR_HEADER_ELEMENT_ARRAY_OPS: PairHeaderElementArrayOps =
    PairHeaderElementArrayOps {
        reset: missing_reset_element_array,
    };

/// `FUN_082ab398`'s fixed `FUN_082b498c` defaults.
const ARRAY_ALLOCATION_HEADER_BYTES: u32 = 0;
const ARRAY_INITIALIZER_ARGUMENT: u32 = 0;
const ARRAY_ALLOCATOR_CALLBACK: u32 = 0;
const ARRAY_ALLOCATOR_CONTEXT: u32 = 0;
const ARRAY_ALLOCATION_FLAGS: u32 = 0;
const ARRAY_ZERO_INITIALIZE: u32 = 0;

/// Byte offset of the `FUN_08185b98` subobject in the grand base.
const GRAND_BASE_BODY_OFFSET_WORDS: usize = 0x2c / 4;
/// Fixed direct-call arguments recovered from the retail ARM ABI.
const GRAND_BASE_BODY_FIELD_COUNT: u32 = 4;
const GRAND_BASE_BODY_FIELD_SIZE: u32 = 0x14;
const GRAND_BASE_BODY_ELEMENT_INITIALIZER: u32 = 0x0828_3a74;
const GRAND_BASE_BODY_INITIALIZER_CONTEXT: u32 = 0;

/// pair_header_grand_base_reset — original: `FUN_082ab398` @ `0x082ab398`
/// (84 bytes; source: `ipod-decomp/decomp/c/029/082ab398_FUN_082ab398.c`).
///
/// Translates the five incoming ARM words into the eleven-word
/// `FUN_082b498c` array-helper ABI. It forwards `this`, `field_count`,
/// `field_size`, `element_initializer`, and `initializer_context` in slots
/// 1, 2, 3, 6, and 7; slots 4, 5, and 8 through 11 are literal zero. The
/// retail wrapper ignores the helper's pointer result, so this function
/// returns `()`. The unported helper remains behind
/// [`PAIR_HEADER_ELEMENT_ARRAY_OPS`]; this wrapper performs no stores and no
/// null checks itself.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_header_grand_base_reset(
    this: *mut u32,
    field_count: u32,
    field_size: u32,
    element_initializer: u32,
    initializer_context: u32,
) {
    let reset = core::ptr::addr_of!(PAIR_HEADER_ELEMENT_ARRAY_OPS.reset).read_volatile();
    reset(
        this,
        field_count,
        field_size,
        ARRAY_ALLOCATION_HEADER_BYTES,
        ARRAY_INITIALIZER_ARGUMENT,
        element_initializer,
        initializer_context,
        ARRAY_ALLOCATOR_CALLBACK,
        ARRAY_ALLOCATOR_CONTEXT,
        ARRAY_ALLOCATION_FLAGS,
        ARRAY_ZERO_INITIALIZE,
    );
}

/// pair_header_grand_base_body_construct — original: `FUN_08185b98` @
/// `0x08185b98` (16 bytes; source:
/// `ipod-decomp/decomp/c/015/08185b98_FUN_08185b98.c`).
///
/// Loads `0x08283a74`, sets `4`, `0x14`, and zero, then tail-branches through
/// the retail ABI adapter to [`pair_header_grand_base_reset`]. The reset
/// receives exactly `(this, 4, 0x14, 0x08283a74, 0)`. Its raw ARM return
/// register remains `this` for this non-allocating call, which is the pointer
/// returned to the enclosing grand-base constructor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_header_grand_base_body_construct(this: *mut u32) -> *mut u32 {
    pair_header_grand_base_reset(
        this,
        GRAND_BASE_BODY_FIELD_COUNT,
        GRAND_BASE_BODY_FIELD_SIZE,
        GRAND_BASE_BODY_ELEMENT_INITIALIZER,
        GRAND_BASE_BODY_INITIALIZER_CONTEXT,
    );
    this
}

/// pair_header_grand_base_construct — original: `FUN_0813eee0` @
/// `0x0813eee0` (20 bytes; source:
/// `ipod-decomp/decomp/c/012/0813eee0_FUN_0813eee0.c`).
///
/// Calls [`pair_header_grand_base_body_construct`] on the +0x2c embedded
/// subobject and returns that pointer rebased by -0x2c. The complete ARM
/// body is `push {r4,lr}; add r0,#0x2c; bl 0x08185b98; sub r0,#0x2c; pop
/// {r4,pc}`: it has no null check or failure branch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_header_grand_base_construct(base: *mut u32) -> *mut u32 {
    pair_header_grand_base_body_construct(base.add(GRAND_BASE_BODY_OFFSET_WORDS))
        .sub(GRAND_BASE_BODY_OFFSET_WORDS)
}

/// PairHeaderBase's vtable literal at 0x0810ebf4.
const PAIR_HEADER_BASE_VTABLE: u32 = 0x0898_1630;

/// pair_header_base_construct — original: `FUN_0810ebbc` @ 0x0810ebbc
/// (56 bytes).
///
/// `0x08981630` at +0, chains to [`pair_header_grand_base_construct`] at +4,
/// clears the two words at +0xac/+0xb0 and the low byte at +0xb4, then zeroes
/// the 0x94-byte interval +4..+0x97. The grand-base result is backed up by
/// one word and returned exactly as the ARM `sub r4, r0, #4` / `mov r0, r4`
/// sequence does. There is no null check or failure branch.
///
/// `base` and the pointer returned by [`pair_header_grand_base_construct`]
/// must describe writable PairHeaderBase storage through the offsets above;
/// the returned pointer must be one `u32` beyond that storage's start.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_header_base_construct(base: *mut u32) -> *mut u32 {
    base.write(PAIR_HEADER_BASE_VTABLE);
    let grand_base = pair_header_grand_base_construct(base.add(1));
    let object = grand_base.sub(1);
    object.add(0xac / 4).write(0);
    object.add(0xb0 / 4).write(0);
    object.cast::<u8>().add(0xb4).write(0);
    core::ptr::write_bytes(grand_base.cast::<u8>(), 0, 0x94);
    object
}

/// pair_header_construct — original: `FUN_08124a38` @ 0x08124a38
/// (36 bytes; 90 `bl` call sites, the only copy).
///
/// Constructs a 200-byte service object at `this`: stores
/// `header_first` at +0 and `header_second` at +4 (the original's
/// `stmia r0!, {r1, r2}`), skips the word at +8, runs the base-class
/// constructor @ 0x0810ebbc on the subobject at +12, backs the result
/// up by 12 to recover `this`, clears the word at +0xc4 and the byte
/// at +8, and returns `this`.
///
/// The base-ctor result is used exactly as in the original — the returned
/// pointer minus 12 is the object — so the concrete base port's return
/// value controls where these trailing clears land.
///
/// # Safety
/// `this` must point at 0xc8 writable, 4-byte-aligned bytes; its base
/// subobject's grand-base dependency must be configured as documented by
/// [`pair_header_base_construct`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_header_construct(
    this: *mut u32,
    header_first: u32,
    header_second: u32,
) -> *mut u32 {
    this.write(header_first);
    this.add(1).write(header_second);
    let object = pair_header_base_construct(this.add(3)).sub(3);
    object.add(0xc4 / 4).write(0);
    object.cast::<u8>().add(8).write(0);
    object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::vec;

    /// Constructor dependency swaps are global; serialize the tests.
    static OPS_LOCKED: AtomicBool = AtomicBool::new(false);

    struct OpsLock;

    fn lock_ops() -> OpsLock {
        while OPS_LOCKED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::thread::yield_now();
        }
        OpsLock
    }

    impl Drop for OpsLock {
        fn drop(&mut self) {
            OPS_LOCKED.store(false, Ordering::Release);
        }
    }

    /// Objects are 200 bytes (0xc8) at the derived constructor's call sites.
    const OBJECT_WORDS: usize = 0xc8 / 4;
    const BASE_WORDS: usize = 0xb8 / 4;
    const FILL: u32 = 0xaaaa_5555;

    struct OpsGuard;

    impl OpsGuard {
        fn install(ops: PairHeaderElementArrayOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(ops);
            }
            OpsGuard
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(
                    PairHeaderElementArrayOps {
                        reset: missing_reset_element_array,
                    },
                );
            }
        }
    }

    static mut ARRAY_CALLS: usize = 0;
    static mut CALL_ORDER: [u8; 2] = [0; 2];
    static mut SEEN_ARRAY_ARGS: [usize; 11] = [0; 11];
    static mut SEEN_VTABLE: u32 = 0;
    static mut SEEN_PREZERO_WORD: u32 = 0;
    static mut SEEN_PRECLEAR_WORD: u32 = 0;

    unsafe fn reset_recording() {
        core::ptr::addr_of_mut!(ARRAY_CALLS).write_volatile(0);
        core::ptr::addr_of_mut!(CALL_ORDER).write_volatile([0; 2]);
        core::ptr::addr_of_mut!(SEEN_ARRAY_ARGS).write_volatile([0; 11]);
        core::ptr::addr_of_mut!(SEEN_VTABLE).write_volatile(0);
        core::ptr::addr_of_mut!(SEEN_PREZERO_WORD).write_volatile(0);
        core::ptr::addr_of_mut!(SEEN_PRECLEAR_WORD).write_volatile(0);
    }

    unsafe extern "C" fn recording_element_array_reset(
        this: *mut u32,
        field_count: u32,
        field_size: u32,
        allocation_header_bytes: u32,
        initializer_argument: u32,
        element_initializer: u32,
        initializer_context: u32,
        allocator_callback: u32,
        allocator_context: u32,
        allocation_flags: u32,
        zero_initialize: u32,
    ) -> *mut u32 {
        let calls = core::ptr::addr_of!(ARRAY_CALLS).read_volatile();
        core::ptr::addr_of_mut!(ARRAY_CALLS).write_volatile(calls + 1);
        core::ptr::addr_of_mut!(CALL_ORDER)
            .cast::<u8>()
            .add(calls)
            .write_volatile(1);
        core::ptr::addr_of_mut!(SEEN_ARRAY_ARGS).write_volatile([
            this as usize,
            field_count as usize,
            field_size as usize,
            allocation_header_bytes as usize,
            initializer_argument as usize,
            element_initializer as usize,
            initializer_context as usize,
            allocator_callback as usize,
            allocator_context as usize,
            allocation_flags as usize,
            zero_initialize as usize,
        ]);
        let grand_base = this.sub(GRAND_BASE_BODY_OFFSET_WORDS);
        let pair_header_base = grand_base.sub(1);
        core::ptr::addr_of_mut!(SEEN_VTABLE).write_volatile(pair_header_base.read());
        core::ptr::addr_of_mut!(SEEN_PREZERO_WORD).write_volatile(grand_base.read());
        core::ptr::addr_of_mut!(SEEN_PRECLEAR_WORD)
            .write_volatile(grand_base.add((0xac - 4) / 4).read());
        // The real helper returns `this` on this non-allocating path. A
        // distinct result proves the wrapper intentionally discards it.
        this.add(4)
    }

    unsafe fn seen_array_args() -> [usize; 11] {
        core::ptr::addr_of!(SEEN_ARRAY_ARGS).read_volatile()
    }

    /// `FUN_082ab398` preserves its five incoming words and materializes all
    /// six literal-zero words in the original eleven-argument helper call.
    #[test]
    fn grand_base_reset_forwards_11_word_abi_and_discards_helper_return() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderElementArrayOps {
            reset: recording_element_array_reset,
        });
        unsafe {
            reset_recording();
            let mut storage = vec![FILL; BASE_WORDS + 8];
            let this = storage.as_mut_ptr().add(1 + GRAND_BASE_BODY_OFFSET_WORDS);

            let returned: () =
                pair_header_grand_base_reset(this, 0x11, 0x22, 0x3333_4444, 0x5555_6666);

            assert_eq!(returned, ());
            assert_eq!(core::ptr::addr_of!(ARRAY_CALLS).read_volatile(), 1);
            assert_eq!(core::ptr::addr_of!(CALL_ORDER).read_volatile()[0], 1);
            assert_eq!(
                seen_array_args(),
                [
                    this as usize,
                    0x11,
                    0x22,
                    ARRAY_ALLOCATION_HEADER_BYTES as usize,
                    ARRAY_INITIALIZER_ARGUMENT as usize,
                    0x3333_4444,
                    0x5555_6666,
                    ARRAY_ALLOCATOR_CALLBACK as usize,
                    ARRAY_ALLOCATOR_CONTEXT as usize,
                    ARRAY_ALLOCATION_FLAGS as usize,
                    ARRAY_ZERO_INITIALIZE as usize,
                ]
            );
        }
    }

    /// `FUN_08185b98` now invokes the direct `FUN_082ab398` port with the
    /// retail literal arguments and keeps its incoming pointer as its result.
    #[test]
    fn grand_base_body_construct_uses_ported_reset_dependency() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderElementArrayOps {
            reset: recording_element_array_reset,
        });
        unsafe {
            reset_recording();
            let mut storage = vec![FILL; BASE_WORDS + 8];
            let grand_base = storage.as_mut_ptr().add(1);
            let body = grand_base.add(GRAND_BASE_BODY_OFFSET_WORDS);

            assert_eq!(pair_header_grand_base_body_construct(body), body);
            assert_eq!(core::ptr::addr_of!(ARRAY_CALLS).read_volatile(), 1);
            assert_eq!(core::ptr::addr_of!(CALL_ORDER).read_volatile()[0], 1);
            assert_eq!(
                seen_array_args(),
                [
                    body as usize,
                    GRAND_BASE_BODY_FIELD_COUNT as usize,
                    GRAND_BASE_BODY_FIELD_SIZE as usize,
                    ARRAY_ALLOCATION_HEADER_BYTES as usize,
                    ARRAY_INITIALIZER_ARGUMENT as usize,
                    GRAND_BASE_BODY_ELEMENT_INITIALIZER as usize,
                    GRAND_BASE_BODY_INITIALIZER_CONTEXT as usize,
                    ARRAY_ALLOCATOR_CALLBACK as usize,
                    ARRAY_ALLOCATOR_CONTEXT as usize,
                    ARRAY_ALLOCATION_FLAGS as usize,
                    ARRAY_ZERO_INITIALIZE as usize,
                ]
            );
        }
    }

    /// `FUN_0813eee0` reaches the direct `FUN_08185b98` port only after
    /// forming its +0x2c body pointer, then rebases that body's pointer.
    #[test]
    fn grand_base_constructor_forwards_body_pointer_and_rebases() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderElementArrayOps {
            reset: recording_element_array_reset,
        });
        unsafe {
            reset_recording();
            let mut storage = vec![FILL; GRAND_BASE_BODY_OFFSET_WORDS + 8];
            let grand_base = storage.as_mut_ptr();
            let result = pair_header_grand_base_construct(grand_base);

            assert_eq!(result, grand_base);
            assert_eq!(core::ptr::addr_of!(ARRAY_CALLS).read_volatile(), 1);
            assert_eq!(
                seen_array_args()[0],
                grand_base.add(GRAND_BASE_BODY_OFFSET_WORDS) as usize,
                "the body port forwards exactly grand_base + 0x2c"
            );
        }
    }

    /// The vtable plant precedes the grand-base chain; the field clears and
    /// zero-fill follow it, with the original base-pointer return.
    #[test]
    fn base_constructor_orders_vtable_chain_and_clears() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderElementArrayOps {
            reset: recording_element_array_reset,
        });
        unsafe {
            reset_recording();
            let mut base = vec![FILL; BASE_WORDS];
            let this = base.as_mut_ptr();
            let ret = pair_header_base_construct(this);

            assert_eq!(ret, this);
            assert_eq!(
                seen_array_args()[0],
                this.add(1 + GRAND_BASE_BODY_OFFSET_WORDS) as usize,
                "grand-base reset receives the grand base + 0x2c"
            );
            assert_eq!(
                core::ptr::addr_of!(SEEN_VTABLE).read_volatile(),
                PAIR_HEADER_BASE_VTABLE,
                "vtable is planted before the chain"
            );
            assert_eq!(
                core::ptr::addr_of!(SEEN_PREZERO_WORD).read_volatile(),
                FILL,
                "zero-fill has not started during the chain"
            );
            assert_eq!(
                core::ptr::addr_of!(SEEN_PRECLEAR_WORD).read_volatile(),
                FILL,
                "trailing fields are cleared after the chain"
            );
            assert_eq!(base[0], PAIR_HEADER_BASE_VTABLE);
            assert!(
                base[1..1 + 0x94 / 4].iter().all(|&word| word == 0),
                "+4..+0x97 is zero-filled"
            );
            assert_eq!(base[0xac / 4], 0);
            assert_eq!(base[0xb0 / 4], 0);
            assert_eq!(base[0xb4 / 4], 0xaaaa_5500);
        }
    }


    /// The derived constructor now calls the concrete base port and retains
    /// its own header/flag/trailing-field behavior.
    #[test]
    fn derived_constructor_uses_ported_base_layout() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderElementArrayOps {
            reset: missing_reset_element_array,
        });
        unsafe {
            let mut object = vec![FILL; OBJECT_WORDS];
            let this = object.as_mut_ptr();
            let ret = pair_header_construct(this, 0x1111_2222, 0x3333_4444);

            assert_eq!(ret, this);
            assert_eq!(object[0], 0x1111_2222);
            assert_eq!(object[1], 0x3333_4444);
            assert_eq!(object[2], 0xaaaa_5500);
            assert_eq!(object[3], PAIR_HEADER_BASE_VTABLE);
            assert!(object[4..4 + 0x94 / 4].iter().all(|&word| word == 0));
            assert_eq!(object[(12 + 0xac) / 4], 0);
            assert_eq!(object[(12 + 0xb0) / 4], 0);
            assert_eq!(object[(12 + 0xb4) / 4], 0xaaaa_5500);
            assert_eq!(object[0xc4 / 4], 0);
        }
    }
}
