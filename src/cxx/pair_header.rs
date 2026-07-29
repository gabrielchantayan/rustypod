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

/// Indirect dispatch for the not-yet-ported base-class constructor
/// (the `TimerOps` precedent in `drivers/timer.rs`).
#[derive(Clone, Copy)]
pub struct PairHeaderOps {
    /// Base-class constructor @ 0x0810ebbc(base) -> base: stores the
    /// class vtable at +0, chains to the grand-base ctor @ 0x0813eee0
    /// at +4, clears the words at +0xac/+0xb0 and the byte at +0xb4,
    /// zeroes 0x94 bytes at +4 (memset @ 0x08037db8), and returns its
    /// argument. Not yet ported.
    pub construct_base: unsafe extern "C" fn(base: *mut u32) -> *mut u32,
}

/// Default stub: leaves the subobject untouched but preserves the
/// return-its-argument dataflow (which the real ctor has), so the
/// derived-class field clears below still land on `this`. On real
/// hardware PAIR_HEADER_OPS must be installed before this port runs.
unsafe extern "C" fn missing_construct_base(base: *mut u32) -> *mut u32 {
    base
}

/// The active base-constructor slot. Defaults to the documented stub
/// above; replaced by host tests (mocks) and eventually by the ported
/// 0x0810ebbc. Written once at init on target; tests serialize access.
pub static mut PAIR_HEADER_OPS: PairHeaderOps = PairHeaderOps {
    construct_base: missing_construct_base,
};

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
/// The base-ctor result is used exactly as in the original — the
/// returned pointer minus 12 is the object — so an override that does
/// not return its argument relocates the trailing clears the same way
/// the firmware would.
///
/// # Safety
/// `this` must point at 0xc8 writable, 4-byte-aligned bytes. The
/// installed `construct_base` must accept the subobject pointer
/// `this + 12`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_header_construct(
    this: *mut u32,
    header_first: u32,
    header_second: u32,
) -> *mut u32 {
    this.write(header_first);
    this.add(1).write(header_second);
    // Reads the fn-pointer field directly rather than through a
    // whole-table read (the timer_schedule_shim gotcha).
    let construct_base =
        core::ptr::addr_of!(PAIR_HEADER_OPS.construct_base).read_volatile();
    let object = construct_base(this.add(3)).sub(3);
    object.add(0xc4 / 4).write(0);
    object.cast::<u8>().add(8).write(0);
    object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::vec;

    /// Ops-table swaps are global; serialize the tests.
    static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    /// Objects are 200 bytes (0xc8) at the call sites.
    const OBJECT_WORDS: usize = 0xc8 / 4;

    struct OpsGuard;

    impl OpsGuard {
        fn install(ops: PairHeaderOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_OPS)
                    .write_volatile(ops);
            }
            OpsGuard
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_OPS).write_volatile(
                    PairHeaderOps {
                        construct_base: missing_construct_base,
                    },
                );
            }
        }
    }

    /// With the default stub the header words land, the flag byte and
    /// trailing word are cleared, and `this` comes back.
    #[test]
    fn default_stub_constructs_header_and_clears_fields() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = OpsGuard::install(PairHeaderOps {
            construct_base: missing_construct_base,
        });
        unsafe {
            let mut object = vec![0xaaaa_5555u32; OBJECT_WORDS];
            let this = object.as_mut_ptr();
            let ret = pair_header_construct(this, 0x1111_2222, 0x3333_4444);
            assert_eq!(ret, this);
            assert_eq!(object[0], 0x1111_2222);
            assert_eq!(object[1], 0x3333_4444);
            // Flag byte at +8 cleared, the other three bytes untouched.
            assert_eq!(object[2], 0xaaaa_5500);
            // Trailing word at +0xc4 cleared.
            assert_eq!(object[0xc4 / 4], 0);
            // The base subobject (+12..+0xc4) is the stub's no-op zone.
            assert_eq!(object[3], 0xaaaa_5555);
            assert_eq!(object[0xc0 / 4], 0xaaaa_5555);
        }
    }

    /// The base ctor receives this+12 and its return value minus 12 is
    /// the object the trailing clears land on.
    #[test]
    fn base_ctor_gets_subobject_and_return_value_is_used() {
        let _lock = OPS_LOCK.lock().unwrap();

        static mut SEEN_BASE: usize = 0;
        unsafe extern "C" fn recording_construct_base(base: *mut u32) -> *mut u32 {
            core::ptr::addr_of_mut!(SEEN_BASE).write_volatile(base as usize);
            base
        }

        let _guard = OpsGuard::install(PairHeaderOps {
            construct_base: recording_construct_base,
        });
        unsafe {
            let mut object = vec![0u32; OBJECT_WORDS];
            let this = object.as_mut_ptr();
            let ret = pair_header_construct(this, 1, 2);
            assert_eq!(ret, this);
            assert_eq!(
                core::ptr::addr_of!(SEEN_BASE).read_volatile(),
                this.add(3) as usize
            );
            assert_eq!(object[0], 1);
            assert_eq!(object[1], 2);
            assert_eq!(object[2], 0);
            assert_eq!(object[0xc4 / 4], 0);
        }
    }
}
