//! SQLite VDBE-operation support recovered from the retailOS SQLite
//! amalgamation.
//!
//! This module currently contains the string accumulator initializer that
//! SQLite's VDBE printf paths use to establish their output buffer.

/// A SQLite `StrAccum` through the last byte written by
/// [`str_accum_init`].
///
/// The retail layout is `zBase`, `zText`, `nChar`, `nAlloc`, `mxAlloc`, then
/// `mallocFailed`, `useMalloc`, and `tooBig` at offsets 0x00..=0x16. Later
/// fields, if any, are deliberately not modeled because this port writes none
/// of them.
#[repr(C)]
pub struct StrAccum {
    pub z_base: *mut u8,
    pub z_text: *mut u8,
    pub n_char: i32,
    pub n_alloc: i32,
    pub mx_alloc: i32,
    pub malloc_failed: u8,
    pub use_malloc: u8,
    pub too_big: u8,
}

// The target is a 32-bit ARM ABI. Keep every recovered store at its original
// byte offset even though host pointers are wider for behavioral tests.
#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(StrAccum, z_base) == 0x00);
    assert!(core::mem::offset_of!(StrAccum, z_text) == 0x04);
    assert!(core::mem::offset_of!(StrAccum, n_char) == 0x08);
    assert!(core::mem::offset_of!(StrAccum, n_alloc) == 0x0c);
    assert!(core::mem::offset_of!(StrAccum, mx_alloc) == 0x10);
    assert!(core::mem::offset_of!(StrAccum, malloc_failed) == 0x14);
    assert!(core::mem::offset_of!(StrAccum, use_malloc) == 0x15);
    assert!(core::mem::offset_of!(StrAccum, too_big) == 0x16);
};

/// str_accum_init — original: `FUN_08384e84` @ 0x08384e84 (44 bytes).
///
/// Source: `ipod-decomp/decomp/c/033/08384e84_FUN_08384e84.c`; the true
/// 44-byte extent is recorded in `ipod-decomp/decomp/functions.csv`. This is
/// SQLite's `sqlite3StrAccumInit`: point both the base and current-text fields
/// at `base`, clear the character count and the `mallocFailed`/`tooBig` flags,
/// retain the supplied initial and maximum capacities, and enable allocation.
/// Rust uses volatile stores only to retain the original's distinct-store
/// structure; this does not change its observable initialization behavior.
///
/// # Safety
/// `accum` must point to writable storage for a [`StrAccum`]. `base` is
/// retained but not dereferenced by this function.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn str_accum_init(
    accum: *mut StrAccum,
    base: *mut u8,
    initial_capacity: i32,
    max_capacity: i32,
) {
    core::ptr::addr_of_mut!((*accum).z_base).write_volatile(base);
    core::ptr::addr_of_mut!((*accum).z_text).write_volatile(base);
    core::ptr::addr_of_mut!((*accum).n_char).write_volatile(0);
    core::ptr::addr_of_mut!((*accum).n_alloc).write_volatile(initial_capacity);
    core::ptr::addr_of_mut!((*accum).mx_alloc).write_volatile(max_capacity);
    core::ptr::addr_of_mut!((*accum).use_malloc).write_volatile(1);
    core::ptr::addr_of_mut!((*accum).too_big).write_volatile(0);
    core::ptr::addr_of_mut!((*accum).malloc_failed).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn initializes_every_recovered_field_without_touching_base_storage() {
        let mut base = [0xa5u8; 8];
        let mut accum = MaybeUninit::<StrAccum>::uninit();

        unsafe {
            str_accum_init(accum.as_mut_ptr(), base.as_mut_ptr(), 37, 1024);
            let accum = accum.assume_init();
            assert_eq!(accum.z_base, base.as_mut_ptr());
            assert_eq!(accum.z_text, base.as_mut_ptr());
            assert_eq!(accum.n_char, 0);
            assert_eq!(accum.n_alloc, 37);
            assert_eq!(accum.mx_alloc, 1024);
            assert_eq!(accum.malloc_failed, 0);
            assert_eq!(accum.use_malloc, 1);
            assert_eq!(accum.too_big, 0);
        }
        assert_eq!(base, [0xa5; 8]);
    }

    #[test]
    fn accepts_null_base_and_signed_capacity_limits_verbatim() {
        let mut accum = MaybeUninit::<StrAccum>::uninit();

        unsafe {
            str_accum_init(accum.as_mut_ptr(), core::ptr::null_mut(), -1, i32::MAX);
            let accum = accum.assume_init();
            assert!(accum.z_base.is_null());
            assert!(accum.z_text.is_null());
            assert_eq!(accum.n_char, 0);
            assert_eq!(accum.n_alloc, -1);
            assert_eq!(accum.mx_alloc, i32::MAX);
            assert_eq!(accum.malloc_failed, 0);
            assert_eq!(accum.use_malloc, 1);
            assert_eq!(accum.too_big, 0);
        }
    }

    #[test]
    fn fields_follow_the_recovered_target_order() {
        assert!(core::mem::offset_of!(StrAccum, z_base) < core::mem::offset_of!(StrAccum, z_text));
        assert!(core::mem::offset_of!(StrAccum, z_text) < core::mem::offset_of!(StrAccum, n_char));
        assert!(core::mem::offset_of!(StrAccum, n_char) < core::mem::offset_of!(StrAccum, n_alloc));
        assert!(core::mem::offset_of!(StrAccum, n_alloc) < core::mem::offset_of!(StrAccum, mx_alloc));
        assert!(core::mem::offset_of!(StrAccum, mx_alloc) < core::mem::offset_of!(StrAccum, malloc_failed));
        assert!(core::mem::offset_of!(StrAccum, malloc_failed) < core::mem::offset_of!(StrAccum, use_malloc));
        assert!(core::mem::offset_of!(StrAccum, use_malloc) < core::mem::offset_of!(StrAccum, too_big));
    }
}
