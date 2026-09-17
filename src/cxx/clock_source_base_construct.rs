//! `clock_source_base_construct` — original: `FUN_082628f4` @ 0x082628f4
//! (20 bytes, including its literal pool word).
//!
//! # Binary verification
//!
//! Raw `osos.dec` (load base 0x08000000) establishes the exact extent
//! 0x082628f4..0x08262907: `ldr r2, [pc, #8]`; `str r2, [r0]`; `strb r1,
//! [r0, #4]`; `bx lr`; `.word 0x089a80b0`. The next real function begins at
//! 0x08262908. Decoding all ARM branch-immediate words finds 4 direct plain
//! `bl` callers and 0 predicated `bl` callers.
//!
//! # Algorithm
//!
//! Initializes the common five-byte prefix of a clock source: installs base
//! vtable 0x089a80b0 at byte offset 0 and writes the caller-supplied kind byte
//! at offset 4. `r0` passes through unchanged. Deliberate deviations: none.

/// Literal-pool word at 0x08262904, installed at `this + 0x00`.
pub const VTABLE_ADDRESS: u32 = 0x089a_80b0;

/// clock_source_base_construct — original: `FUN_082628f4` @ 0x082628f4
/// (20 bytes including the literal pool; 4 plain `bl` callers, 0 predicated).
///
/// Initializes a clock source object's common `{ u32 vtable, u8 kind }` prefix
/// and returns `this` unchanged. Neither pointer nor alignment is checked.
///
/// # Safety
///
/// `this` must point to at least five writable bytes and be 4-byte aligned.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clock_source_base_construct(this: *mut u8, kind: u8) -> *mut u8 {
    unsafe {
        this.cast::<u32>().write_volatile(VTABLE_ADDRESS);
        this.add(4).write_volatile(kind);
    }
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(align(4))]
    struct Clock([u8; 16]);

    #[test]
    fn it_initializes_the_prefix_and_returns_this_for_all_kind_bytes() {
        for kind in [0, 1, 0x5a, u8::MAX] {
            let mut clock = Clock([0xa5; 16]);

            let returned = unsafe { clock_source_base_construct(clock.0.as_mut_ptr(), kind) };

            assert_eq!(returned, clock.0.as_mut_ptr());
            assert_eq!(u32::from_ne_bytes(clock.0[..4].try_into().unwrap()), VTABLE_ADDRESS);
            assert_eq!(clock.0[4], kind);
            assert_eq!(clock.0[5..], [0xa5; 11]);
        }
    }
}
