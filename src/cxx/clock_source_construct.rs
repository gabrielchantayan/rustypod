//! `clock_source_construct` — original: `FUN_08262958` @ 0x08262958
//! (28 bytes).
//!
//! The constructor of the kind-1 clock object — the sibling of the
//! destructor `clock_source_destroy` @ 0x08262908 (already ported) and
//! of the kind-0 constructor @ 0x08262a9c (not yet ported).
//!
//! # Extent, binary-verified
//!
//! Ghidra reports 24 bytes; the true extent is **28**. The listing from
//! `work/firmware/osos.dec` (load base 0x08000000, not Ghidra):
//!
//! ```text
//! 08262958  push {r4, lr}
//! 0826295c  mov  r1, #1
//! 08262960  bl   0x082628f4        @ the base constructor
//! 08262964  ldr  r1, [pc, #4]      @ -> 0x08262970
//! 08262968  str  r1, [r0]          @ this->vtable = <derived vtable>
//! 0826296c  pop  {r4, pc}
//! 08262970  .word 0x089a80d0       @ the derived vtable literal
//! 08262974  push {r4, r5, r6, lr}  @ the next function
//! ```
//!
//! Ghidra dropped the trailing literal-pool word, its most common
//! mis-size. The next function's prologue at 0x08262974 pins the end.
//!
//! # Call count, binary-verified
//!
//! Decoding every B/BL word in osos.dec: **41 `bl` call sites, 0 plain
//! `b`, 0 predicated forms**, and **0 occurrences of 0x08262958 as a
//! data word** — never reached through a vtable, always bound
//! statically, which is how a compiler calls a known-type constructor.
//!
//! # Algorithm
//!
//! The canonical derived-class constructor over the base @ 0x082628f4,
//! whose own body (also binary-verified, 16 bytes with its literal @
//! 0x08262904) is the whole object layout:
//!
//! ```text
//! 082628f4  ldr  r2, [pc, #8]   @ 0x089a80b0
//! 082628f8  str  r2, [r0]       @ this->vtable = base vtable
//! 082628fc  strb r1, [r0, #4]   @ this->kind   = kind
//! 08262900  bx   lr             @ r0 passes through: returns this
//! ```
//!
//! So the object is `{ u32 vtable, u8 kind }` and this constructor
//! builds it with `kind = 1`, then replaces the base vtable
//! 0x089a80b0 with the derived one, 0x089a80d0. r0 is live across the
//! `bl` (the base returns `this`), so the vtable store and the return
//! value both follow the base's r0 — the store targets the base's
//! *return value*, not the original argument, and the port keeps that
//! contract.
//!
//! # What the object is
//!
//! A clock, by the call sites (the analysis `clock_source_destroy`
//! recorded, independently re-verified here): the canonical use @
//! 0x081944b4 constructs one on the stack, calls the function pointer
//! at vtable +0xc with an out pointer to a `{ sec, nsec }` pair,
//! converts that through 0x082a1c30 (`sec * 1000 + nsec / 1000000`,
//! dividing by the literal 1000000), and destroys the clock. The other
//! reference to 0x089a80d0 in the image is the literal pool @
//! 0x08190a34 of a function that inlines this constructor — and the
//! very next pool word @ 0x08190a38 is 0x000f4240 = 1000000, the
//! millis conversion constant. The `kind` byte selects which clock;
//! the sibling constructor @ 0x08262a9c is byte-identical in shape
//! with `kind = 0` and vtable 0x089a80f0.
//!
//! # Anomaly, documented not invented
//!
//! The installed vtable 0x089a80d0 does not fully decode in the image.
//! Its words (0x089a80d0..0x089a80ec, binary-verified):
//!
//! ```text
//! +0x00  0x083a5a54   decodes as a plausible entry (a forwarding thunk)
//! +0x04  0x081c0030   mid-function: inside FUN_081bff64 (0x81bff64..0x81c0030)
//! +0x08  0x081c0038   mid-function: same body
//! +0x0c  0x081c0028   mid-function: same body — yet call sites blx it
//! +0x10  0x0810301c   a Ghidra function entry (364 bytes)
//! +0x14  0x081030ac   inside FUN_0810301c
//! +0x18  0x08102f80   inside FUN_08102f44
//! +0x1c  0x00000000
//! ```
//!
//! The +0x0c word is what 0x081944b4 loads and `blx`s, but the bytes
//! there are the middle of a conditional path of the surrounding
//! function (fallen into from `beq` @ 0x081c0024), not an entry; the
//! sibling kind-0 vtable @ 0x089a80f0 has literal zeros at +0x00,
//! +0x08, +0x0c, +0x10, +0x14. A whole-image scan finds no data word
//! or code reference that could patch these slots at runtime. The
//! bytes are not a decryption artifact — the surrounding tables and
//! code are coherent, and the mid-function targets sit inside
//! functions whose internal branches are self-consistent. The
//! resolution is unknown; possibilities (a RAM snapshot tail, an
//! overlay) are speculation and are deliberately NOT encoded anywhere
//! in this port: the constructor's own contract is only to *install
//! the pointer*, which it does verbatim.
//!
//! # Deviations
//!
//! The base constructor @ 0x082628f4 is not yet ported, so the call
//! goes through the [`CLOCK_SOURCE_OPS`] dispatch seam (house
//! pattern). Its default, [`default_construct_base`], is NOT a stub:
//! it reproduces the base's four binary-verified instructions exactly
//! (store base vtable, store kind byte, return this), so with the
//! default wired the port is behaviorally identical to the original
//! and hook-ready. A future port of 0x082628f4 replaces the default
//! without touching this caller. The original's `mov r1, #1` is the
//! [`CLOCK_KIND`] constant. No frame deviations otherwise: one `bl`,
//! one literal-word load, one store.

/// The derived vtable this constructor installs — the original's
/// literal pool word @ 0x08262970, binary-verified.
pub const VTABLE_ADDRESS: u32 = 0x089a_80d0;

/// The base vtable the base constructor @ 0x082628f4 installs before
/// this constructor overwrites it — its literal pool word @
/// 0x08262904, binary-verified.
pub const BASE_VTABLE_ADDRESS: u32 = 0x089a_80b0;

/// The `kind` byte of the clock this constructor builds — the
/// original's `mov r1, #1` @ 0x0826295c. The sibling constructor @
/// 0x08262a9c passes 0.
pub const CLOCK_KIND: u8 = 1;

/// The one callee of [`clock_source_construct`] that has no port yet.
#[derive(Clone, Copy)]
pub struct ClockSourceOps {
    /// Original 0x082628f4: the base constructor. Installs the base
    /// vtable at `this + 0x00`, stores `kind` at `this + 0x04`, and
    /// returns `this`.
    pub construct_base: unsafe extern "C" fn(this: *mut u8, kind: u8) -> *mut u8,
}

/// Default boundary before 0x082628f4 is ported: a binary-verified
/// reproduction of its four instructions (`str 0x089a80b0, [r0]`;
/// `strb r1, [r0, #4]`; r0 passes through), not a stub.
unsafe extern "C" fn default_construct_base(this: *mut u8, kind: u8) -> *mut u8 {
    unsafe {
        this.cast::<u32>().write(BASE_VTABLE_ADDRESS);
        *this.add(4) = kind;
    }
    this
}

/// Wired default for [`CLOCK_SOURCE_OPS`].
pub const DEFAULT_CLOCK_SOURCE_OPS: ClockSourceOps = ClockSourceOps {
    construct_base: default_construct_base,
};

/// Active model of the constructor's unported callee. A later port of
/// 0x082628f4 replaces the default without changing this caller.
pub static mut CLOCK_SOURCE_OPS: ClockSourceOps = DEFAULT_CLOCK_SOURCE_OPS;

#[inline(always)]
unsafe fn ops() -> ClockSourceOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CLOCK_SOURCE_OPS)) }
}

/// clock_source_construct — original: `FUN_08262958` @ 0x08262958
/// (28 bytes; 41 `bl` call sites, 0 `b`, 0 predicated, 0 data-word
/// references, binary-scanned over the whole image).
///
/// Constructs a kind-1 clock object at `this`: runs the base
/// constructor with `kind = 1`, then installs the derived vtable
/// 0x089a80d0 at `this + 0x00`, and returns the base's return value
/// (which is `this` for the stock base). Like the original, neither
/// `this` nor the base's return is null-checked.
///
/// # Safety
///
/// `this` must point at 5 writable bytes, 4-byte aligned for the
/// vtable word, or be whatever the wired [`CLOCK_SOURCE_OPS`] base
/// returns instead.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clock_source_construct(this: *mut u8) -> *mut u8 {
    let this = unsafe { (ops().construct_base)(this, CLOCK_KIND) };
    unsafe { this.cast::<u32>().write(VTABLE_ADDRESS) };
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    /// Serializes the tests that swap [`CLOCK_SOURCE_OPS`]; the
    /// default-ops tests take it too, so no test observes another's
    /// recorder.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    struct OpsRestore;

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe { CLOCK_SOURCE_OPS = DEFAULT_CLOCK_SOURCE_OPS };
        }
    }

    fn lock_ops() -> (std::sync::MutexGuard<'static, ()>, OpsRestore) {
        let guard = OPS_LOCK.lock().unwrap();
        (guard, OpsRestore)
    }

    /// A 16-byte, 4-aligned object with room to spare around the
    /// `{ u32 vtable, u8 kind }` layout.
    #[repr(align(4))]
    struct Clock([u8; 16]);

    impl Clock {
        fn filled(fill: u8) -> Self {
            Clock([fill; 16])
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }

        fn vtable_word(&self) -> u32 {
            u32::from_ne_bytes(self.0[0..4].try_into().unwrap())
        }
    }

    #[test]
    fn it_builds_a_kind1_clock_and_returns_this() {
        let (_guard, _restore) = lock_ops();
        let mut clock = Clock::filled(0xa5);

        let returned = unsafe { clock_source_construct(clock.ptr()) };

        assert_eq!(returned, clock.ptr());
        assert_eq!(clock.vtable_word(), VTABLE_ADDRESS);
        assert_eq!(clock.0[4], 1, "the kind byte");
        assert_eq!(clock.0[5..], [0xa5; 11][..], "no other byte is touched");
    }

    static mut BASE_CALLS: usize = 0;
    static mut BASE_SEEN_THIS: *mut u8 = core::ptr::null_mut();
    static mut BASE_SEEN_KIND: u8 = 0xff;
    const BASE_SENTINEL_VTABLE: u32 = 0xdead_beef;

    /// A base-constructor recorder that also plants a sentinel vtable,
    /// so the caller proves the derived store lands *after* the base
    /// ran.
    unsafe extern "C" fn recording_construct_base(this: *mut u8, kind: u8) -> *mut u8 {
        unsafe {
            BASE_CALLS += 1;
            BASE_SEEN_THIS = this;
            BASE_SEEN_KIND = kind;
            this.cast::<u32>().write(BASE_SENTINEL_VTABLE);
            *this.add(4) = kind;
        }
        this
    }

    #[test]
    fn the_base_runs_first_with_kind1_then_the_derived_vtable_lands() {
        let (_guard, _restore) = lock_ops();
        unsafe {
            BASE_CALLS = 0;
            CLOCK_SOURCE_OPS = ClockSourceOps {
                construct_base: recording_construct_base,
            };
        }
        let mut clock = Clock::filled(0xa5);

        let returned = unsafe { clock_source_construct(clock.ptr()) };

        assert_eq!(returned, clock.ptr());
        assert_eq!(unsafe { BASE_CALLS }, 1, "the base runs exactly once");
        assert_eq!(unsafe { BASE_SEEN_THIS }, clock.ptr());
        assert_eq!(unsafe { BASE_SEEN_KIND }, 1, "mov r1, #1");
        assert_eq!(
            clock.vtable_word(),
            VTABLE_ADDRESS,
            "the derived store overwrote the base's sentinel, so it ran second"
        );
        assert_eq!(clock.0[4], 1);
    }

    static mut REDIRECT_TARGET: *mut u8 = core::ptr::null_mut();

    /// A base that returns a *different* object, to pin that the
    /// vtable store and the return value follow the base's r0, not the
    /// constructor's argument — the original's `str r1, [r0]` uses the
    /// r0 the base left behind.
    unsafe extern "C" fn redirecting_construct_base(_this: *mut u8, _kind: u8) -> *mut u8 {
        unsafe { REDIRECT_TARGET }
    }

    #[test]
    fn the_vtable_store_and_return_follow_the_base_r0() {
        let (_guard, _restore) = lock_ops();
        let mut elsewhere = Clock::filled(0xa5);
        unsafe {
            REDIRECT_TARGET = elsewhere.ptr();
            CLOCK_SOURCE_OPS = ClockSourceOps {
                construct_base: redirecting_construct_base,
            };
        }
        let mut clock = Clock::filled(0xa5);

        let returned = unsafe { clock_source_construct(clock.ptr()) };

        assert_eq!(returned, elsewhere.ptr());
        assert_eq!(elsewhere.vtable_word(), VTABLE_ADDRESS);
        assert_eq!(
            clock.vtable_word(),
            0xa5a5_a5a5,
            "the argument object is untouched when the base redirects"
        );
    }

    #[test]
    fn the_default_base_reproduces_the_stock_four_instructions() {
        let (_guard, _restore) = lock_ops();
        let mut clock = Clock::filled(0xa5);

        let base = DEFAULT_CLOCK_SOURCE_OPS.construct_base;
        let returned = unsafe { base(clock.ptr(), 0x5a) };

        assert_eq!(returned, clock.ptr(), "r0 passes through");
        assert_eq!(clock.vtable_word(), BASE_VTABLE_ADDRESS);
        assert_eq!(clock.0[4], 0x5a, "the kind byte passes through");
        assert_eq!(clock.0[5..], [0xa5; 11][..], "no other byte is touched");
    }
}
