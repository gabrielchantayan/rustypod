//! The two-word-header derived-class constructor the application layer
//! runs to bring up its 200-byte service objects (90 `bl` call sites),
//! plus the concrete base class's own destructor @ 0x0810ec10 — the
//! teardown `crate::app::pair_header_destruct` chains into.
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
    /// pointer result, which `FUN_082ab398` forwards in r0.
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
/// retail wrapper performs no stores and no null checks itself, and its ARM
/// body leaves `FUN_082b498c`'s pointer result in r0 all the way to the
/// `pop {r4, r5, r6, pc}` — Ghidra's `void` return is a C-level fiction the
/// binary does not support. That result is load-bearing: the only caller
/// family is the four-argument adapter @ 0x082ab234 (ported as
/// `crate::runtime::cpp_array_construct::cpp_array_construct`), whose own
/// callers chain on the returned array base (e.g. the 0x081b80b4 site
/// stores into `ret + 0x60` and passes `ret + 100` to the next adapter
/// call). The port therefore forwards the helper's result. The unported
/// helper remains behind [`PAIR_HEADER_ELEMENT_ARRAY_OPS`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_header_grand_base_reset(
    this: *mut u32,
    field_count: u32,
    field_size: u32,
    element_initializer: u32,
    initializer_context: u32,
) -> *mut u32 {
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
    )
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

/// Byte-offset-in-words of the grand-base body *inside the base object*.
/// The base stores its vtable in word 0 and puts the grand base at +4, so
/// this is one word past [`GRAND_BASE_BODY_OFFSET_WORDS`] — 0x30 bytes,
/// the original's `add r0, r4, #48`.
const BASE_BODY_OFFSET_WORDS: usize = GRAND_BASE_BODY_OFFSET_WORDS + 1;

/// The two unported teardowns [`pair_header_base_destruct`] calls.
#[derive(Clone, Copy)]
pub struct PairHeaderBaseDestructOps {
    /// Original 0x0810e908 (52 bytes, a standalone function — the word
    /// before it is a `pop {..., pc}`). It returns the base's optionally
    /// owned 28-byte payload: if the ownership byte at +0xb4 is set and
    /// the pointer at +0x04 is non-NULL, it releases that pointer either
    /// to the pool at +0xb0 through the ported `heap_free` (0x0819d4dc)
    /// or, when there is no pool, to the global heap through the ported
    /// `free_wrapper` (0x080e7970). A default-constructed base has all
    /// three fields cleared by `pair_header_base_construct`, so this is a
    /// no-op on that path.
    pub release_owned_payload: unsafe extern "C" fn(*mut u32),
    /// Original 0x08185bac (32 bytes: seven instructions plus the literal
    /// pool word 0x08283a80 at 0x08185bcc). The mirror image of the ported
    /// [`pair_header_grand_base_body_construct`] @ 0x08185b98 — it passes
    /// `(this, 4, 0x14, 0x08283a80)` to the array-helper adapter at
    /// 0x082ab3ec, which destroys the four 20-byte elements through the
    /// ported `__cpp_finalise` (0x080336d8) and skips everything when the
    /// element destructor is NULL. It returns `this`.
    pub destroy_grand_base_body: unsafe extern "C" fn(*mut u32) -> *mut u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_release_owned_payload(base: *mut u32) {
    let release: unsafe extern "C" fn(*mut u32) =
        unsafe { core::mem::transmute(0x0810_e908usize) };
    unsafe { release(base) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_destroy_grand_base_body(body: *mut u32) -> *mut u32 {
    let destroy: unsafe extern "C" fn(*mut u32) -> *mut u32 =
        unsafe { core::mem::transmute(0x0818_5bacusize) };
    unsafe { destroy(body) }
}

/// Host defaults. Both callees free storage, so unlike the construction
/// table's benign stand-ins these panic: a silent no-op would let a test
/// claim a teardown that never happened.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_owned_payload(_base: *mut u32) {
    panic!("pair_header_base_destruct requires payload release 0x0810e908")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_grand_base_body(_body: *mut u32) -> *mut u32 {
    panic!("pair_header_base_destruct requires body teardown 0x08185bac")
}

/// Active teardowns for [`pair_header_base_destruct`].
#[cfg(target_os = "none")]
pub static mut PAIR_HEADER_BASE_DESTRUCT_OPS: PairHeaderBaseDestructOps =
    PairHeaderBaseDestructOps {
        release_owned_payload: firmware_release_owned_payload,
        destroy_grand_base_body: firmware_destroy_grand_base_body,
    };

#[cfg(not(target_os = "none"))]
pub static mut PAIR_HEADER_BASE_DESTRUCT_OPS: PairHeaderBaseDestructOps =
    PairHeaderBaseDestructOps {
        release_owned_payload: missing_release_owned_payload,
        destroy_grand_base_body: missing_destroy_grand_base_body,
    };

/// pair_header_base_destruct — original: `FUN_0810ec10` @ 0x0810ec10
/// (44 bytes: ten instructions plus the literal pool word at 0x0810ec38
/// that Ghidra's 40-byte extent drops; the next function starts at
/// 0x0810ec3c. 56 `bl` call sites and no `b` tail calls, both verified by
/// decoding every branch word in osos.dec).
///
/// The non-deleting destructor of the same 0xb8-byte base object
/// [`pair_header_base_construct`] @ 0x0810ebbc builds — the two share the
/// vtable literal [`PAIR_HEADER_BASE_VTABLE`], which occurs in exactly
/// seven places in the image, all of them literal pools of that one
/// class's constructors and this destructor. The address itself occurs in
/// no data word, so it fills no vtable slot: every call site reaches it
/// directly, and the deleting form is the separate thunk @ 0x0810ebf8
/// (`cmp r0,#0; bl 0x0810ec10; b operator_delete`).
///
/// It reinstalls the vtable, releases the optionally owned payload, and
/// destroys the grand base's element array at +0x30, returning `base`
/// through that teardown's own result (`sub r0, r0, #48`).
///
/// The construction and destruction chains are deliberately not mirror
/// images. Construction goes `base -> grand base at +4 -> body at
/// grandbase+0x2c`; destruction skips the middle hop and calls the body
/// teardown at base+0x30 directly, because the grand base has nothing of
/// its own to unwind. The port reproduces the collapsed chain rather than
/// re-introducing a wrapper the original does not call.
///
/// # Safety
///
/// `base` must point at 0xb8 writable, word-aligned bytes holding a
/// constructed base object, and the pointer returned by
/// `destroy_grand_base_body` must be 0x30 bytes into that storage. All as
/// in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_header_base_destruct(base: *mut u32) -> *mut u32 {
    let ops =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PAIR_HEADER_BASE_DESTRUCT_OPS)) };
    unsafe { base.write(PAIR_HEADER_BASE_VTABLE) };
    unsafe { (ops.release_owned_payload)(base) };
    unsafe { (ops.destroy_grand_base_body)(base.add(BASE_BODY_OFFSET_WORDS)) }
        .sub(BASE_BODY_OFFSET_WORDS)
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
    use std::vec;

    /// Constructor dependency swaps are global; the seam is shared with
    /// `runtime::cpp_array_construct`'s tests, so both serialize on the
    /// crate-wide lock rather than a module-private one.
    fn lock_ops() -> std::sync::MutexGuard<'static, ()> {
        crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap()
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
        // distinct result proves the wrapper forwards r0 verbatim.
        this.add(4)
    }

    unsafe fn seen_array_args() -> [usize; 11] {
        core::ptr::addr_of!(SEEN_ARRAY_ARGS).read_volatile()
    }

    /// `FUN_082ab398` preserves its five incoming words, materializes all
    /// six literal-zero words in the original eleven-argument helper call,
    /// and forwards the helper's pointer result in r0 untouched.
    #[test]
    fn grand_base_reset_forwards_11_word_abi_and_helper_return() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderElementArrayOps {
            reset: recording_element_array_reset,
        });
        unsafe {
            reset_recording();
            let mut storage = vec![FILL; BASE_WORDS + 8];
            let this = storage.as_mut_ptr().add(1 + GRAND_BASE_BODY_OFFSET_WORDS);

            let returned =
                pair_header_grand_base_reset(this, 0x11, 0x22, 0x3333_4444, 0x5555_6666);

            // The recording helper returns `this.add(4)`; retail r0 keeps it.
            assert_eq!(returned, this.add(4));
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

#[cfg(test)]
mod base_destruct_tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// The teardown table is one global; serialize the tests that swap it.
    static DESTRUCT_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<Call> = Vec::new();
    /// Non-null forces the body teardown's return value, which is how the
    /// rebase test proves the port works off the callee's pointer.
    static mut BODY_RESULT: *mut u32 = core::ptr::null_mut();

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        /// `vtable` is read back through the argument, so recording it
        /// proves the vtable store precedes the release.
        ReleaseOwnedPayload { base: usize, vtable: u32 },
        DestroyGrandBaseBody { body: usize },
    }

    unsafe extern "C" fn recording_release_owned_payload(base: *mut u32) {
        unsafe {
            CALLS.push(Call::ReleaseOwnedPayload {
                base: base as usize,
                vtable: base.read(),
            })
        };
    }

    unsafe extern "C" fn recording_destroy_grand_base_body(body: *mut u32) -> *mut u32 {
        unsafe {
            CALLS.push(Call::DestroyGrandBaseBody { body: body as usize });
            let forced = core::ptr::read_volatile(core::ptr::addr_of!(BODY_RESULT));
            if forced.is_null() {
                body
            } else {
                forced
            }
        }
    }

    fn mock() -> MutexGuard<'static, ()> {
        let guard = DESTRUCT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(PAIR_HEADER_BASE_DESTRUCT_OPS).write_volatile(
                PairHeaderBaseDestructOps {
                    release_owned_payload: recording_release_owned_payload,
                    destroy_grand_base_body: recording_destroy_grand_base_body,
                },
            );
            CALLS.clear();
            BODY_RESULT = core::ptr::null_mut();
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            core::ptr::addr_of_mut!(PAIR_HEADER_BASE_DESTRUCT_OPS).write_volatile(
                PairHeaderBaseDestructOps {
                    release_owned_payload: missing_release_owned_payload,
                    destroy_grand_base_body: missing_destroy_grand_base_body,
                },
            );
        }
        drop(guard);
    }

    fn calls() -> Vec<Call> {
        unsafe { CALLS.clone() }
    }

    /// The class's whole 0xb8-byte extent, as `pair_header_base_construct`
    /// fills it (its last field is the ownership byte at +0xb4).
    #[repr(align(4))]
    struct Base([u8; 0xb8]);

    #[test]
    fn the_vtable_is_reinstalled_before_anything_is_released() {
        let guard = mock();
        let mut object = Base([0xa5; 0xb8]);
        let base = object.0.as_mut_ptr().cast::<u32>();
        unsafe {
            let returned = pair_header_base_destruct(base);

            assert_eq!(
                calls(),
                std::vec![
                    Call::ReleaseOwnedPayload {
                        base: base as usize,
                        vtable: PAIR_HEADER_BASE_VTABLE,
                    },
                    Call::DestroyGrandBaseBody {
                        body: base.add(BASE_BODY_OFFSET_WORDS) as usize,
                    },
                ],
                "vtable store, then release(this), then destroy(this + 0x30)"
            );
            assert_eq!(base.read(), PAIR_HEADER_BASE_VTABLE);
            assert_eq!(returned, base, "and `this` comes back out");
        }
        restore(guard);
    }

    #[test]
    fn the_body_teardown_lands_exactly_0x30_bytes_in() {
        let guard = mock();
        let mut object = Base([0; 0xb8]);
        let base = object.0.as_mut_ptr().cast::<u32>();
        unsafe {
            pair_header_base_destruct(base);
            let Call::DestroyGrandBaseBody { body } = calls()[1] else {
                unreachable!("the second call is the body teardown")
            };
            assert_eq!(
                body - base as usize,
                0x30,
                "the vtable word plus the grand base's own 0x2c offset"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_return_value_is_rebased_off_the_callee_result() {
        let guard = mock();
        let mut object = Base([0; 0xb8]);
        let mut elsewhere = Base([0; 0xb8]);
        let base = object.0.as_mut_ptr().cast::<u32>();
        unsafe {
            for shift in [0usize, 4, 0x30] {
                let relocated = elsewhere.0.as_mut_ptr().add(shift).cast::<u32>();
                BODY_RESULT = relocated;
                assert_eq!(
                    pair_header_base_destruct(base),
                    relocated.byte_sub(0x30),
                    "shift {shift:#x}: the result is the teardown's pointer minus 0x30",
                );
            }
        }
        restore(guard);
    }

    #[test]
    fn nothing_outside_the_vtable_word_is_written() {
        let guard = mock();
        let mut object = Base([0x5a; 0xb8]);
        let base = object.0.as_mut_ptr().cast::<u32>();
        unsafe { pair_header_base_destruct(base) };
        // Ownership byte, pool word and payload pointer belong to
        // 0x0810e908; the element array belongs to 0x08185bac.
        assert!(
            object.0[4..].iter().all(|&b| b == 0x5a),
            "the destructor itself stores only the vtable"
        );
        restore(guard);
    }
}
