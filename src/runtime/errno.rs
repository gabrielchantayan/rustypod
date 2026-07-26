//! Ports of the ARM ADS 1.0.1 runtime-environment (libspace) accessors:
//!
//! - `__rt_libspace` — original: `FUN_0803204c` @ 0x0803204c (8 bytes).
//!   Returns a pointer to the per-thread libspace block. In osos the block
//!   is a single static in DRAM at load address 0x08b31774 (the function is
//!   just `ldr r0, =0x08b31774; bx lr`).
//! - `__rt_errno_addr` — original: `FUN_0802ecb4` @ 0x0802ecb4 (12 bytes).
//!   Returns libspace+0, i.e. `&libspace.errno`.
//! - errno get — original: `FUN_08032168` @ 0x08032168 (16 bytes),
//!   ported as `errno_get`. Returns `*__rt_errno_addr()`.
//! - errno set — original: `FUN_08032178` @ 0x08032178 (20 bytes),
//!   ported as `errno_set`. Stores its argument to `*__rt_errno_addr()`.
//! - `__rt_ctype_table_addr` — original: `FUN_0802eca0` @ 0x0802eca0
//!   (16 bytes). Returns libspace+0x24, the address of the ctype-table
//!   pointer slot (a `*mut u32`, not the table itself).
//! - `__rt_fp_status_addr` — original: `FUN_08036d60` @ 0x08036d60
//!   (16 bytes). Returns libspace+4, the soft-float status word.
//!
//! Libspace layout (word offsets known from osos callers):
//! - +0x00 `errno` — read/written by __rt_errno_addr and callers.
//! - +0x04 fp status word — address returned by __rt_fp_status_addr
//!   (sole reader: the float exception path in the fplib region).
//! - +0x08 heap descriptor — used by the malloc family.
//! - +0x14 alloc arena break / +0x1c stack-guard reserve — used by the
//!   allocator and the arena extension (see malloc_rt.rs).
//! - +0x20..+0x34 the five LC category slots (collate, ctype, monetary,
//!   numeric, time — one word per category bit), filled in by setlocale
//!   (setlocale_core @ 0x080307bc, install path @ 0x08030860; ported in
//!   runtime/locale.rs, which models these five words as `LC_SLOTS` —
//!   host pointers don't fit the u32 words kept here for layout). The
//!   ctype slot (+0x24) stores block+1 so index -1/EOF lands on a guard
//!   byte (see ctype.rs). Zero-initialized: null until installed.
//! - +0x3c atexit table pointer — used by the atexit/exit machinery.
//!
//! All other words are reserved (layout not yet recovered). The true extent
//! of the original block past +0x3c is unknown; `Libspace` is sized to
//! 0x40 bytes (16 words), covering every offset observed in use.
//!
//! Deviation: the original block lives at a fixed DRAM address and is
//! zeroed by the startup code; this port models it as a zero-initialized
//! `static mut LIBSPACE` at whatever address the linker picks. Accessors
//! go through `libspace()`/`__rt_libspace()` so the difference is invisible
//! to ported callers. `errno_get`/`errno_set` are extern "C" wrappers with
//! semantic names; the original names are the bare addresses above.
//! Pointer slots (`ctype_table`, `atexit_table`) are modeled as raw `u32`
//! address words rather than Rust pointers so the `repr(C)` layout stays
//! byte-faithful to the 32-bit original on 64-bit build hosts.

/// The ADS per-thread runtime block. osos runs single-threaded with one
/// static block at 0x08b31774; here it is a `static mut` (see module docs).
#[repr(C)]
pub struct Libspace {
    /// +0x00: errno value (`__rt_errno_addr` returns a pointer to this).
    pub errno: i32,
    /// +0x04: soft-float status word (`__rt_fp_status_addr` returns a
    /// pointer to this).
    pub fp_status: u32,
    /// +0x08: heap descriptor, used by the malloc family.
    pub heap_desc: u32,
    /// +0x0c..+0x14: reserved (layout not yet recovered).
    reserved_0c: [u32; 2],
    /// +0x14: alloc arena bound (low), used by the allocator.
    pub alloc_arena_lo: u32,
    /// +0x18: reserved (layout not yet recovered).
    reserved_18: u32,
    /// +0x1c: alloc arena bound (high), used by the allocator.
    pub alloc_arena_hi: u32,
    /// +0x20: LC_COLLATE slot (the locale directory ptr 0x08985c06 when
    /// installed; see runtime/locale.rs).
    pub lc_collate: u32,
    /// +0x24: LC_CTYPE slot / ctype table pointer (raw address word),
    /// filled in by setlocale @ 0x08030860 — stored biased by +1 so index
    /// -1/EOF reads a guard byte. Zero (null) until the first setlocale.
    pub ctype_table: u32,
    /// +0x28: LC_MONETARY slot / +0x2c: LC_NUMERIC slot (block pointers
    /// read by localeconv_fill @ 0x080354b8; runtime/locale.rs).
    pub lc_monetary_numeric: [u32; 2],
    /// +0x30: LC_TIME slot (directory ptr, like +0x20).
    pub lc_time: u32,
    /// +0x34..+0x3c: reserved (layout not yet recovered).
    reserved_34: [u32; 2],
    /// +0x3c: atexit table pointer (raw address word), used by the
    /// atexit/exit machinery.
    pub atexit_table: u32,
}

// Pointer slots are raw `u32` address words (not Rust pointers) so the
// layout is byte-faithful to the 32-bit original on every build host.

const _: () = assert!(core::mem::size_of::<Libspace>() == 0x40);

/// The single libspace block. Original: DRAM static at load address
/// 0x08b31774, zeroed by startup; here a zero-initialized `static mut`.
static mut LIBSPACE: Libspace = Libspace {
    errno: 0,
    fp_status: 0,
    heap_desc: 0,
    reserved_0c: [0; 2],
    alloc_arena_lo: 0,
    reserved_18: 0,
    alloc_arena_hi: 0,
    lc_collate: 0,
    ctype_table: 0,
    lc_monetary_numeric: [0; 2],
    lc_time: 0,
    reserved_34: [0; 2],
    atexit_table: 0,
};

/// Pointer to the libspace block (semantic-name companion of
/// `__rt_libspace`).
pub unsafe fn libspace() -> *mut Libspace {
    core::ptr::addr_of_mut!(LIBSPACE)
}

/// __rt_libspace — original: `FUN_0803204c` @ 0x0803204c (8 bytes).
///
/// `ldr r0, =0x08b31774; bx lr` — returns the libspace block address.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_libspace() -> *mut Libspace {
    libspace()
}

/// __rt_errno_addr — original: `FUN_0802ecb4` @ 0x0802ecb4 (12 bytes).
///
/// Calls __rt_libspace and returns it unchanged: errno sits at libspace+0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_errno_addr() -> *mut i32 {
    &mut (*__rt_libspace()).errno
}

/// __rt_fp_status_addr — original: `FUN_08036d60` @ 0x08036d60 (16 bytes).
///
/// `bl __rt_libspace; add r0, r0, #4` — the ADS soft-float status word
/// lives at libspace+4. Sole caller in osos: the float exception path in
/// the fplib region (@ 0x083ecb94, unported); the `__ieee_status` entry
/// retailOS actually ships is a stub that never touches it (fp_scalb.rs).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_fp_status_addr() -> *mut u32 {
    &mut (*__rt_libspace()).fp_status
}

/// errno get — original: `FUN_08032168` @ 0x08032168 (16 bytes).
///
/// `bl __rt_errno_addr; ldr r0, [r0]` — reads the errno word.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn errno_get() -> i32 {
    *__rt_errno_addr()
}

/// errno set — original: `FUN_08032178` @ 0x08032178 (20 bytes).
///
/// `bl __rt_errno_addr; str value, [r0]` — writes the errno word.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn errno_set(value: i32) {
    *__rt_errno_addr() = value;
}

/// __rt_ctype_table_addr — original: `FUN_0802eca0` @ 0x0802eca0 (16 bytes).
///
/// Returns libspace+0x24: the address of the ctype-table pointer slot
/// (setlocale stores through it; ctype readers load the pointer from it).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_ctype_table_addr() -> *mut u32 {
    &mut (*__rt_libspace()).ctype_table
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn errno_round_trip() {
        unsafe {
            assert_eq!(errno_get(), 0, "errno must start zeroed");
            errno_set(42);
            assert_eq!(errno_get(), 42);
            errno_set(-1);
            assert_eq!(errno_get(), -1);
            errno_set(0);
            assert_eq!(errno_get(), 0);
        }
    }

    #[test]
    fn fp_status_addr_is_libspace_plus_4() {
        unsafe {
            let slot = __rt_fp_status_addr();
            assert_eq!(slot as usize - libspace() as usize, 4);
            assert_eq!(*slot, 0, "fp status starts zeroed");
        }
    }

    #[test]
    fn errno_addr_points_into_libspace_at_offset_zero() {
        unsafe {
            assert_eq!(__rt_errno_addr(), libspace() as *mut i32);
            assert_eq!(__rt_errno_addr(), __rt_libspace() as *mut i32);
            // Writing through errno_addr must be visible via errno_get.
            *__rt_errno_addr() = 7;
            assert_eq!((*libspace()).errno, 7);
            *__rt_errno_addr() = 0;
        }
    }

    #[test]
    fn ctype_table_slot_default_state() {
        unsafe {
            // Zero-initialized (null) until setlocale fills it in.
            assert_eq!((*libspace()).ctype_table, 0);
            let slot = __rt_ctype_table_addr();
            assert_eq!(slot, &mut (*libspace()).ctype_table as *mut u32);
            // The slot sits exactly at libspace+0x24.
            assert_eq!(
                slot as usize - libspace() as usize,
                0x24,
                "ctype slot must be at libspace+0x24"
            );
            assert_eq!(*slot, 0);
        }
    }

    #[test]
    fn known_offsets_match_original_layout() {
        unsafe {
            let base = libspace() as usize;
            assert_eq!(&(*libspace()).errno as *const i32 as usize - base, 0x00);
            assert_eq!(&(*libspace()).heap_desc as *const u32 as usize - base, 0x08);
            assert_eq!(&(*libspace()).alloc_arena_lo as *const u32 as usize - base, 0x14);
            assert_eq!(&(*libspace()).alloc_arena_hi as *const u32 as usize - base, 0x1c);
            assert_eq!(&(*libspace()).ctype_table as *const u32 as usize - base, 0x24);
            assert_eq!(&(*libspace()).lc_collate as *const u32 as usize - base, 0x20);
            assert_eq!(
                (*libspace()).lc_monetary_numeric.as_ptr() as usize - base,
                0x28
            );
            assert_eq!(&(*libspace()).lc_time as *const u32 as usize - base, 0x30);
            assert_eq!(&(*libspace()).atexit_table as *const u32 as usize - base, 0x3c);
        }
    }
}
