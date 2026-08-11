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

/// Host-test dispatch for the still-unported `FUN_082ab398` grand-base-body
/// constructor. `pair_header_grand_base_body_construct` is the direct port
/// of its caller and supplies this fixed ARM ABI argument set.
#[derive(Clone, Copy)]
pub struct PairHeaderGrandBaseBodyOps {
    /// Constructs `this` with the original fixed arguments.
    pub construct: unsafe extern "C" fn(
        this: *mut u32,
        field_count: u32,
        field_size: u32,
        type_descriptor: u32,
        flags: u32,
    ) -> *mut u32,
}

/// Default stand-in for the still-unported `FUN_082ab398`. It preserves the
/// pointer-return contract but does not initialize any fields.
unsafe extern "C" fn missing_construct_grand_base_body(
    this: *mut u32,
    _field_count: u32,
    _field_size: u32,
    _type_descriptor: u32,
    _flags: u32,
) -> *mut u32 {
    this
}

/// The active `FUN_082ab398` host-test seam. It remains only because that
/// callee has not yet been ported.
pub static mut PAIR_HEADER_GRAND_BASE_BODY_OPS: PairHeaderGrandBaseBodyOps =
    PairHeaderGrandBaseBodyOps {
        construct: missing_construct_grand_base_body,
    };

/// Byte offset of the `FUN_08185b98` subobject in the grand base.
const GRAND_BASE_BODY_OFFSET_WORDS: usize = 0x2c / 4;
/// Fixed direct-call arguments recovered from the retail ARM ABI.
const GRAND_BASE_BODY_FIELD_COUNT: u32 = 4;
const GRAND_BASE_BODY_FIELD_SIZE: u32 = 0x14;
const GRAND_BASE_BODY_TYPE_DESCRIPTOR: u32 = 0x0828_3a74;
const GRAND_BASE_BODY_FLAGS: u32 = 0;

/// pair_header_grand_base_body_construct — original: `FUN_08185b98` @
/// `0x08185b98` (16 bytes; source:
/// `ipod-decomp/decomp/c/015/08185b98_FUN_08185b98.c`).
///
/// Tail-calls the grand-base body constructor: the retail entry loads
/// `0x08283a74`, sets the remaining fixed arguments to `4`, `0x14`, and
/// `0`, enters the ARM ABI adapter at `0x082ab234`, and returns the exact
/// result from its direct `0x082ab398` call. This port calls that still
/// unported target through the narrow host-test seam with the same argument
/// order and return dataflow; it performs no stores or null checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_header_grand_base_body_construct(this: *mut u32) -> *mut u32 {
    let construct = core::ptr::addr_of!(PAIR_HEADER_GRAND_BASE_BODY_OPS.construct).read_volatile();
    construct(
        this,
        GRAND_BASE_BODY_FIELD_COUNT,
        GRAND_BASE_BODY_FIELD_SIZE,
        GRAND_BASE_BODY_TYPE_DESCRIPTOR,
        GRAND_BASE_BODY_FLAGS,
    )
}

/// pair_header_grand_base_construct — original: `FUN_0813eee0` @
/// `0x0813eee0` (20 bytes; source:
/// `ipod-decomp/decomp/c/012/0813eee0_FUN_0813eee0.c`).
///
/// Constructs the grand base by calling [`pair_header_grand_base_body_construct`]
/// on the +0x2c subobject, then returns that callee's result rebased by -0x2c.
/// The complete ARM body is `push {r4,lr}; add r0,#0x2c; bl 0x08185b98; sub
/// r0,#0x2c; pop {r4,pc}`: it has no null check and preserves the callee's
/// returned pointer rather than assuming it equals the argument.
///
/// Deviation: the still-unported direct callee `FUN_082ab398` is isolated
/// behind [`PAIR_HEADER_GRAND_BASE_BODY_OPS`] for host tests; the +0x2c
/// argument and -0x2c return rebase are otherwise direct translations.
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
        fn install(ops: PairHeaderGrandBaseBodyOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_GRAND_BASE_BODY_OPS).write_volatile(ops);
            }
            OpsGuard
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_GRAND_BASE_BODY_OPS).write_volatile(
                    PairHeaderGrandBaseBodyOps {
                        construct: missing_construct_grand_base_body,
                    },
                );
            }
        }
    }

    static mut BODY_CALLS: usize = 0;
    static mut SEEN_GRAND_BASE: usize = 0;
    static mut SEEN_FIELD_COUNT: u32 = 0;
    static mut SEEN_FIELD_SIZE: u32 = 0;
    static mut SEEN_TYPE_DESCRIPTOR: u32 = 0;
    static mut SEEN_FLAGS: u32 = 0;
    static mut SEEN_VTABLE: u32 = 0;
    static mut SEEN_PREZERO_WORD: u32 = 0;
    static mut SEEN_PRECLEAR_WORD: u32 = 0;

    unsafe fn reset_recording() {
        core::ptr::addr_of_mut!(BODY_CALLS).write_volatile(0);
        core::ptr::addr_of_mut!(SEEN_GRAND_BASE).write_volatile(0);
        core::ptr::addr_of_mut!(SEEN_FIELD_COUNT).write_volatile(0);
        core::ptr::addr_of_mut!(SEEN_FIELD_SIZE).write_volatile(0);
        core::ptr::addr_of_mut!(SEEN_TYPE_DESCRIPTOR).write_volatile(0);
        core::ptr::addr_of_mut!(SEEN_FLAGS).write_volatile(0);
    }

    unsafe extern "C" fn recording_grand_base_body(
        base: *mut u32,
        field_count: u32,
        field_size: u32,
        type_descriptor: u32,
        flags: u32,
    ) -> *mut u32 {
        let calls = core::ptr::addr_of!(BODY_CALLS).read_volatile();
        core::ptr::addr_of_mut!(BODY_CALLS).write_volatile(calls + 1);
        core::ptr::addr_of_mut!(SEEN_GRAND_BASE).write_volatile(base as usize);
        core::ptr::addr_of_mut!(SEEN_FIELD_COUNT).write_volatile(field_count);
        core::ptr::addr_of_mut!(SEEN_FIELD_SIZE).write_volatile(field_size);
        core::ptr::addr_of_mut!(SEEN_TYPE_DESCRIPTOR).write_volatile(type_descriptor);
        core::ptr::addr_of_mut!(SEEN_FLAGS).write_volatile(flags);
        let grand_base = base.sub(GRAND_BASE_BODY_OFFSET_WORDS);
        let pair_header_base = grand_base.sub(1);
        core::ptr::addr_of_mut!(SEEN_VTABLE).write_volatile(pair_header_base.read());
        core::ptr::addr_of_mut!(SEEN_PREZERO_WORD).write_volatile(grand_base.read());
        core::ptr::addr_of_mut!(SEEN_PRECLEAR_WORD)
            .write_volatile(grand_base.add((0xac - 4) / 4).read());
        base
    }

    unsafe extern "C" fn shifted_grand_base_body(
        base: *mut u32,
        _field_count: u32,
        _field_size: u32,
        _type_descriptor: u32,
        _flags: u32,
    ) -> *mut u32 {
        base.add(4)
    }

    unsafe extern "C" fn recording_shifted_grand_base_body(
        base: *mut u32,
        field_count: u32,
        field_size: u32,
        type_descriptor: u32,
        flags: u32,
    ) -> *mut u32 {
        recording_grand_base_body(base, field_count, field_size, type_descriptor, flags).add(4)
    }

    /// `FUN_08185b98` forwards the precise five-argument ABI for
    /// `FUN_082ab398` and returns that target's pointer unchanged.
    #[test]
    fn grand_base_body_construct_forwards_abi_and_return() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderGrandBaseBodyOps {
            construct: recording_grand_base_body,
        });
        unsafe {
            reset_recording();
            let mut storage = vec![FILL; BASE_WORDS + 8];
            let grand_base = storage.as_mut_ptr().add(1);
            let body = grand_base.add(GRAND_BASE_BODY_OFFSET_WORDS);

            assert_eq!(pair_header_grand_base_body_construct(body), body);
            assert_eq!(core::ptr::addr_of!(BODY_CALLS).read_volatile(), 1);
            assert_eq!(core::ptr::addr_of!(SEEN_GRAND_BASE).read_volatile(), body as usize);
            assert_eq!(
                core::ptr::addr_of!(SEEN_FIELD_COUNT).read_volatile(),
                GRAND_BASE_BODY_FIELD_COUNT
            );
            assert_eq!(
                core::ptr::addr_of!(SEEN_FIELD_SIZE).read_volatile(),
                GRAND_BASE_BODY_FIELD_SIZE
            );
            assert_eq!(
                core::ptr::addr_of!(SEEN_TYPE_DESCRIPTOR).read_volatile(),
                GRAND_BASE_BODY_TYPE_DESCRIPTOR
            );
            assert_eq!(core::ptr::addr_of!(SEEN_FLAGS).read_volatile(), GRAND_BASE_BODY_FLAGS);
        }
    }

    /// `FUN_0813eee0` reaches the direct `FUN_08185b98` port only after
    /// forming its +0x2c body pointer, then rebases that exact result.
    #[test]
    fn grand_base_constructor_forwards_body_result_and_rebases() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderGrandBaseBodyOps {
            construct: recording_shifted_grand_base_body,
        });
        unsafe {
            reset_recording();
            let mut storage = vec![FILL; GRAND_BASE_BODY_OFFSET_WORDS + 8];
            let grand_base = storage.as_mut_ptr();
            let result = pair_header_grand_base_construct(grand_base);

            assert_eq!(result, grand_base.add(4));
            assert_eq!(core::ptr::addr_of!(BODY_CALLS).read_volatile(), 1);
            assert_eq!(
                core::ptr::addr_of!(SEEN_GRAND_BASE).read_volatile(),
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
        let _guard = OpsGuard::install(PairHeaderGrandBaseBodyOps {
            construct: recording_grand_base_body,
        });
        unsafe {
            let mut base = vec![FILL; BASE_WORDS];
            let this = base.as_mut_ptr();
            let ret = pair_header_base_construct(this);

            assert_eq!(ret, this);
            assert_eq!(
                core::ptr::addr_of!(SEEN_GRAND_BASE).read_volatile(),
                this.add(1 + GRAND_BASE_BODY_OFFSET_WORDS) as usize,
                "grand-base body receives the grand base + 0x2c"
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

    /// The ARM constructor derives both its stores and return from the
    /// grand-base result, rather than assuming that result equals its input.
    #[test]
    fn base_constructor_preserves_grand_base_return_dataflow() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderGrandBaseBodyOps {
            construct: shifted_grand_base_body,
        });
        unsafe {
            let mut storage = vec![FILL; BASE_WORDS + 8];
            let base = storage.as_mut_ptr().add(1);
            let ret = pair_header_base_construct(base);
            let shifted_object = base.add(4);

            assert_eq!(ret, shifted_object);
            assert_eq!(base.read(), PAIR_HEADER_BASE_VTABLE);
            assert_eq!(shifted_object.add(0xac / 4).read(), 0);
            assert_eq!(shifted_object.add(0xb0 / 4).read(), 0);
            assert_eq!(shifted_object.cast::<u8>().add(0xb4).read(), 0);
        }
    }

    /// The derived constructor now calls the concrete base port and retains
    /// its own header/flag/trailing-field behavior.
    #[test]
    fn derived_constructor_uses_ported_base_layout() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderGrandBaseBodyOps {
            construct: missing_construct_grand_base_body,
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
