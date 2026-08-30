//! `ui_font_handle_for_name` — original: `FUN_082756fc` @ `0x082756fc`
//! (44 bytes; 38 verified direct `bl` call sites, 0 predicated).
//!
//! # Algorithm
//!
//! The wrapper zero-initializes an 8-byte stack local and, only when the
//! font `name` pointer (`r1`) is non-NULL, calls the font-handle resolver
//! at `0x08275044` as `(&local, name, size, style)` — the original's
//! `movne r0, sp; blne 0x08275044` passes `r2`/`r3` through untouched, so
//! the caller's size and style words reach the resolver even though
//! Ghidra's decompilation drops them from the call. The local's two words
//! are then stored to `out` unconditionally (`ldrd r0, [sp]; stm r4,
//! {r0, r1}`), so a NULL name yields a zero handle. There is no NULL
//! guard on `out`.
//!
//! The 8-byte result is the current-font pair of the draw state: the
//! setter at `0x0826421c` copies it verbatim into the draw-state record at
//! +0x20/+0x24 (the member zero-initialized by `embedded_pair_construct`)
//! and derives the style byte at +0x28 from the first word. Call-site
//! names are fonts — `"Helvetica"` (0x08186a38), `"MonoHope LCD"` /
//! `"MonoHope TV"` (0x081cde5c) — with point sizes 0xc / 0x14 / 6 in `r2`
//! and a small style selector (0 or 2) in `r3`. The resolver at
//! `0x08275044` (its own 108-byte function: hash, registry lookup via
//! `0x0829bea4`, register-on-miss via `0x08275490`, one-time init flag at
//! `0x089cc8d4`) remains unported behind the boundary below.

/// ABI of the unported font-handle resolver at retailOS address
/// `0x08275044`.
///
/// Resolves `(name, size, style)` into an 8-byte font handle written to
/// `out`, and also returns that handle in `r0:r1`. The original wrapper
/// ignores the register return and reloads the stack local, so callers of
/// this seam must treat the written `out` words as authoritative.
pub type FontHandleResolver =
    unsafe extern "C" fn(out: *mut u64, name: *const u8, size: u32, style: u32) -> u64;

/// RetailOS load address of the resolver reached by this wrapper.
pub const FONT_HANDLE_RESOLVER_ADDRESS: usize = 0x0827_5044;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_font_handle_resolver(
    out: *mut u64,
    name: *const u8,
    size: u32,
    style: u32,
) -> u64 {
    let resolver: FontHandleResolver = core::mem::transmute(FONT_HANDLE_RESOLVER_ADDRESS);
    resolver(out, name, size, style)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_font_handle_resolver(
    _out: *mut u64,
    _name: *const u8,
    _size: u32,
    _style: u32,
) -> u64 {
    panic!("ui_font_handle_for_name requires resolver 0x08275044")
}

/// Active boundary for the unported `0x08275044` resolver.
///
/// Target builds call the resident retailOS function; host tests install a
/// recorder.
#[cfg(target_os = "none")]
pub static mut FONT_HANDLE_RESOLVER: FontHandleResolver = firmware_font_handle_resolver;

/// Active host boundary for the unported `0x08275044` resolver.
#[cfg(not(target_os = "none"))]
pub static mut FONT_HANDLE_RESOLVER: FontHandleResolver = missing_font_handle_resolver;

#[inline(always)]
unsafe fn font_handle_resolver_entry() -> FontHandleResolver {
    core::ptr::addr_of!(FONT_HANDLE_RESOLVER).read_volatile()
}

/// `ui_font_handle_for_name` — original: `FUN_082756fc` @ `0x082756fc`
/// (44 bytes; 38 verified direct `bl` call sites, all unconditional).
///
/// Writes the 8-byte font handle for `(name, size, style)` to `out`. A
/// NULL `name` skips the resolver entirely and stores a zero handle; any
/// non-NULL name — even an empty string — reaches the resolver. The store
/// to `out` is unconditional and is a pair of word stores in the original
/// (`stm r4, {r0, r1}`), so `out` needs only 4-byte alignment; the port
/// preserves both the alignment contract and the word stores.
///
/// Deliberate deviation: Rust reaches the fixed resident resolver through
/// a volatile typed boundary rather than emitting the stock `blne`; this
/// preserves the ABI while permitting host verification. The resolver's
/// `r0:r1` return is discarded, exactly as the original discards it in
/// favor of the stack local.
///
/// # Safety
///
/// `out` must be writable for 8 bytes at 4-byte alignment. `name`, when
/// non-NULL, must satisfy the unported resolver's ABI (a NUL-terminated
/// font name). The original performs no validation of either.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_font_handle_for_name(
    out: *mut u64,
    name: *const u8,
    size: u32,
    style: u32,
) {
    let mut handle: u64 = 0;
    if !name.is_null() {
        font_handle_resolver_entry()(&mut handle, name, size, style);
    }
    // Two aligned word stores, matching `stm r4, {r0, r1}`: the original
    // requires only 4-byte alignment of `out`, and a byte-wise unaligned
    // u64 store would emit eight `strb` on ARMv5TE.
    let words = out as *mut u32;
    words.write(handle as u32);
    words.add(1).write((handle >> 32) as u32);
}

#[cfg(test)]
pub(crate) unsafe fn reset_font_handle_resolver() {
    core::ptr::addr_of_mut!(FONT_HANDLE_RESOLVER).write_volatile(missing_font_handle_resolver);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static mut RECEIVED_NAME: *const u8 = core::ptr::null();
    static mut RECEIVED_SIZE: u32 = 0;
    static mut RECEIVED_STYLE: u32 = 0;
    static mut RECEIVED_OUT_WORD: u32 = 0;
    static mut CALLS: u32 = 0;

    /// Records every forwarded word, then writes the canned handle through
    /// the received `out` pointer exactly like the firmware resolver
    /// (`stm r5, {r0, r1}`), proving the wrapper stores what the resolver
    /// left in its out buffer.
    unsafe extern "C" fn recording_resolver(
        out: *mut u64,
        name: *const u8,
        size: u32,
        style: u32,
    ) -> u64 {
        RECEIVED_NAME = name;
        RECEIVED_SIZE = size;
        RECEIVED_STYLE = style;
        CALLS += 1;
        let handle = u64::from(RECEIVED_OUT_WORD) << 32 | 0x5566_7788;
        out.write_unaligned(handle);
        handle
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                reset_font_handle_resolver();
                RECEIVED_NAME = core::ptr::null();
                RECEIVED_SIZE = 0;
                RECEIVED_STYLE = 0;
                RECEIVED_OUT_WORD = 0;
                CALLS = 0;
            }
        }
    }

    #[test]
    fn null_name_stores_a_zero_handle_without_calling_the_resolver() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock().expect("test lock poisoned");
        let _reset = Reset;
        let mut out: u64 = 0xdead_beef_cafe_f00d;
        unsafe {
            core::ptr::addr_of_mut!(FONT_HANDLE_RESOLVER).write_volatile(recording_resolver);
            ui_font_handle_for_name(&mut out, core::ptr::null(), 0xc, 2);
            assert_eq!(out, 0);
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn named_font_is_resolved_and_stored_unconditionally() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock().expect("test lock poisoned");
        let _reset = Reset;
        let name = b"Helvetica\0";
        let mut out: u64 = 0;
        unsafe {
            RECEIVED_OUT_WORD = 0x1122_3344;
            core::ptr::addr_of_mut!(FONT_HANDLE_RESOLVER).write_volatile(recording_resolver);
            ui_font_handle_for_name(&mut out, name.as_ptr(), 0x14, 2);
            assert_eq!(CALLS, 1);
            assert_eq!(RECEIVED_NAME, name.as_ptr());
            assert_eq!(RECEIVED_SIZE, 0x14);
            assert_eq!(RECEIVED_STYLE, 2);
            assert_eq!(out, 0x1122_3344_5566_7788);
        }
    }

    #[test]
    fn empty_name_still_reaches_the_resolver() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock().expect("test lock poisoned");
        let _reset = Reset;
        let name = b"\0";
        let mut out: u64 = 0;
        unsafe {
            core::ptr::addr_of_mut!(FONT_HANDLE_RESOLVER).write_volatile(recording_resolver);
            ui_font_handle_for_name(&mut out, name.as_ptr(), 6, 0);
            assert_eq!(CALLS, 1);
            assert_eq!(RECEIVED_NAME, name.as_ptr());
            assert_eq!(out, 0x5566_7788);
        }
    }

    #[test]
    fn four_byte_aligned_out_is_stored_without_fault() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock().expect("test lock poisoned");
        let _reset = Reset;
        // The original's `stm r4, {r0, r1}` requires only word alignment of
        // `out`; place the handle at offset 4 of a 12-byte, 8-aligned
        // buffer so an 8-alignment assumption would fault or corrupt.
        let mut buf = [0xaaaa_aaaa_u32; 3];
        unsafe {
            core::ptr::addr_of_mut!(FONT_HANDLE_RESOLVER).write_volatile(recording_resolver);
            let out = buf.as_mut_ptr().add(1) as *mut u64;
            ui_font_handle_for_name(out, core::ptr::null(), 0, 0);
            assert_eq!(buf, [0xaaaa_aaaa, 0, 0]);
        }
    }
}
