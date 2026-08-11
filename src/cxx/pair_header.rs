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

/// Indirect dispatch for the unported grand-base body constructor
/// `FUN_08185b98`. [`pair_header_grand_base_construct`] wraps this target:
/// it passes the base's +0x2c subobject and rebases the returned pointer.
#[derive(Clone, Copy)]
pub struct PairHeaderBaseOps {
    /// Constructor for the grand-base body at `base + 0x2c`.
    pub construct_grand_base_body: unsafe extern "C" fn(base: *mut u32) -> *mut u32,
}

/// Default stand-in for `FUN_08185b98`. It preserves that function's
/// pointer-return contract but does not initialize its fields.
unsafe extern "C" fn missing_construct_grand_base_body(base: *mut u32) -> *mut u32 {
    base
}

/// The active unported-grand-base-body slot. Target initialization must
/// replace this model before complete grand-base construction is required.
pub static mut PAIR_HEADER_BASE_OPS: PairHeaderBaseOps = PairHeaderBaseOps {
    construct_grand_base_body: missing_construct_grand_base_body,
};

/// Byte offset of the `FUN_08185b98` subobject in the grand base.
const GRAND_BASE_BODY_OFFSET_WORDS: usize = 0x2c / 4;

/// pair_header_grand_base_construct — original: `FUN_0813eee0` @
/// `0x0813eee0` (20 bytes; source:
/// `ipod-decomp/decomp/c/012/0813eee0_FUN_0813eee0.c`).
///
/// Constructs the grand base by calling its unported body constructor
/// `FUN_08185b98` on the +0x2c subobject, then returns that callee's result
/// rebased by -0x2c. The complete ARM body is `push {r4,lr}; add r0,#0x2c;
/// bl 0x08185b98; sub r0,#0x2c; pop {r4,pc}`: it has no null check and
/// preserves the callee's returned pointer rather than assuming it equals
/// the argument.
///
/// Deviation: the unported direct callee uses [`PAIR_HEADER_BASE_OPS`], the
/// established local seam; the function's +0x2c argument and -0x2c return
/// rebase are otherwise direct translations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_header_grand_base_construct(base: *mut u32) -> *mut u32 {
    let construct_grand_base_body =
        core::ptr::addr_of!(PAIR_HEADER_BASE_OPS.construct_grand_base_body).read_volatile();
    construct_grand_base_body(base.add(GRAND_BASE_BODY_OFFSET_WORDS))
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
        fn install(ops: PairHeaderBaseOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_BASE_OPS).write_volatile(ops);
            }
            OpsGuard
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_BASE_OPS).write_volatile(
                    PairHeaderBaseOps {
                        construct_grand_base_body: missing_construct_grand_base_body,
                    },
                );
            }
        }
    }

    static mut SEEN_GRAND_BASE: usize = 0;
    static mut SEEN_VTABLE: u32 = 0;
    static mut SEEN_PREZERO_WORD: u32 = 0;
    static mut SEEN_PRECLEAR_WORD: u32 = 0;

    unsafe extern "C" fn recording_grand_base_body(base: *mut u32) -> *mut u32 {
        core::ptr::addr_of_mut!(SEEN_GRAND_BASE).write_volatile(base as usize);
        let grand_base = base.sub(GRAND_BASE_BODY_OFFSET_WORDS);
        let pair_header_base = grand_base.sub(1);
        core::ptr::addr_of_mut!(SEEN_VTABLE).write_volatile(pair_header_base.read());
        core::ptr::addr_of_mut!(SEEN_PREZERO_WORD).write_volatile(grand_base.read());
        core::ptr::addr_of_mut!(SEEN_PRECLEAR_WORD)
            .write_volatile(grand_base.add((0xac - 4) / 4).read());
        base
    }

    unsafe extern "C" fn shifted_grand_base_body(base: *mut u32) -> *mut u32 {
        base.add(4)
    }

    unsafe extern "C" fn recording_shifted_grand_base_body(base: *mut u32) -> *mut u32 {
        core::ptr::addr_of_mut!(SEEN_GRAND_BASE).write_volatile(base as usize);
        base.add(4)
    }

    /// `FUN_0813eee0` calls the +0x2c body constructor first, then returns
    /// that exact pointer rebased by -0x2c.
    #[test]
    fn grand_base_constructor_forwards_body_result_and_rebases() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderBaseOps {
            construct_grand_base_body: recording_shifted_grand_base_body,
        });
        unsafe {
            let mut storage = vec![FILL; GRAND_BASE_BODY_OFFSET_WORDS + 8];
            let grand_base = storage.as_mut_ptr();
            let result = pair_header_grand_base_construct(grand_base);

            assert_eq!(result, grand_base.add(4));
            assert_eq!(
                core::ptr::addr_of!(SEEN_GRAND_BASE).read_volatile(),
                grand_base.add(GRAND_BASE_BODY_OFFSET_WORDS) as usize,
                "the body seam receives exactly grand_base + 0x2c"
            );
        }
    }

    /// The vtable plant precedes the grand-base chain; the field clears and
    /// zero-fill follow it, with the original base-pointer return.
    #[test]
    fn base_constructor_orders_vtable_chain_and_clears() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderBaseOps {
            construct_grand_base_body: recording_grand_base_body,
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
        let _guard = OpsGuard::install(PairHeaderBaseOps {
            construct_grand_base_body: shifted_grand_base_body,
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
        let _guard = OpsGuard::install(PairHeaderBaseOps {
            construct_grand_base_body: missing_construct_grand_base_body,
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
