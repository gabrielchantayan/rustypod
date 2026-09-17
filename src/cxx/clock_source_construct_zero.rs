//! `clock_source_construct_zero` — original: `FUN_08262a9c` @ 0x08262a9c.
//!
//! # Binary verification
//!
//! Raw `osos.dec` (load base 0x08000000) gives the true **28-byte** extent,
//! not Ghidra's 24 bytes:
//!
//! ```text
//! 08262a9c  push {r4, lr}; mov r1, #0; bl 0x082628f4
//! 08262aa8  ldr r1, [pc, #4]; str r1, [r0]; pop {r4, pc}
//! 08262ab4  .word 0x089a80f0
//! 08262ab8  push {r2, r3, lr}       @ next function
//! ```
//!
//! Four direct, unconditional `bl` call sites and no predicated `bl` calls
//! target this constructor. It runs the shared base constructor with kind 0,
//! then replaces the base vtable with 0x089a80f0. As in the ARM sequence, the
//! store and return follow r0 returned by the base constructor.
//!
//! # Deliberate deviation
//!
//! None. The shared base constructor 0x082628f4 is now ported directly.

/// Literal-pool vtable word at 0x08262ab4.
pub const VTABLE_ADDRESS: u32 = 0x089a_80f0;
const CLOCK_KIND: u8 = 0;

/// clock_source_construct_zero — original: `FUN_08262a9c` @ 0x08262a9c
/// (28 bytes; 4 plain `bl` call sites, 0 predicated `bl` call sites).
///
/// Builds the kind-0 clock object at `this`, installing its derived vtable
/// after the base constructor returns. Neither pointer is null-checked.
///
/// # Safety
///
/// `this` must point to at least five writable bytes, aligned for its vtable
/// word, or the base constructor must return another valid object pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clock_source_construct_zero(this: *mut u8) -> *mut u8 {
    let this = unsafe { super::clock_source_base_construct::clock_source_base_construct(this, CLOCK_KIND) };
    unsafe { this.cast::<u32>().write(VTABLE_ADDRESS) };
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(align(4))]
    struct Clock([u8; 16]);

    impl Clock {
        fn word(&self) -> u32 {
            u32::from_ne_bytes(self.0[..4].try_into().unwrap())
        }
    }

    #[test]
    fn it_builds_a_kind_zero_clock_without_touching_neighbours() {
        let mut clock = Clock([0xa5; 16]);

        let returned = unsafe { clock_source_construct_zero(clock.0.as_mut_ptr()) };

        assert_eq!(returned, clock.0.as_mut_ptr());
        assert_eq!(clock.word(), VTABLE_ADDRESS);
        assert_eq!(clock.0[4], 0, "mov r1, #0 reaches the base");
        assert_eq!(clock.0[5..], [0xa5; 11]);
    }
}
