//! Export of a retailOS counted byte string into a length-prefixed
//! UTF-16 buffer: the thin stack-frame wrapper all five callers use.
//!
//! Port:
//! - [`string_export_counted_utf16`] — original: `FUN_0805a8b4` @
//!   **0x0805a8b4** (48 bytes; **5 `bl` call sites**, all unconditional
//!   plain `bl`, verified by decoding every ARM B/BL word in `osos.dec`:
//!   0x080514a8, 0x080fe220, 0x08106f00, 0x0813e8cc, 0x082a3830; Ghidra's
//!   "5 bl" report counts these callers — the body itself issues exactly
//!   **1 plain `bl` and 0 predicated `bl`s**). The next distinct function
//!   begins at 0x0805a8e4 (`stmdb sp!,{r4-r7,lr}`), confirming the
//!   48-byte extent.
//!
//! ## What it is
//!
//! Decoded from the raw ARM at 0x0805a8b4 (load base 0x08000000):
//!
//! ```text
//! 0805a8b4  stmdb sp!, {r1,r2,r3,r4,r5,lr}  @ 24-byte frame; the r1-r3
//!                                          @  spill slots double as the
//!                                          @  callee's stack args/slot
//! 0805a8b8  mov   r4, r2            @ save dst (arg3)
//! 0805a8bc  mov   r2, #0xff        @ capacity = 0xff code units
//! 0805a8c0  add   r3, sp, #0x8     @ &result_slot (the pushed-r3 slot)
//! 0805a8c4  strd  r2, r3, [sp,#0x0]@ stack args 5/6: {0xff, &slot}
//! 0805a8c8  mov   r2, r1           @ forward caller's r1 into the
//!                                  @ callee's DEAD r2
//! 0805a8cc  mov   r1, #0x0         @ aux selector = 0 (no escape pass)
//! 0805a8d0  add   r3, r4, #0x2     @ dst_units = dst + 2 bytes
//! 0805a8d4  bl    0x0805ab44       @ status = impl(src, 0, dead,
//!                                  @   dst+2, 0xff, &slot)
//! 0805a8d8  ldr   r1, [sp,#0x8]    @ reload result slot
//! 0805a8dc  strh  r1, [r4,#0x0]    @ *(u16 *)dst = (u16)slot
//! 0805a8e0  ldmia sp!, {r1,r2,r3,r4,r5,pc}  @ r0 = status passthrough
//! ```
//!
//! The callee @ 0x0805ab44 (unported, 344 bytes through 0x0805ac9c)
//! rebuilds `src` — a counted byte string {u16 length @ +0, NUL-terminated
//! bytes @ +2}, per `string_object_assign_cstr(temp, src + 2)` — as a
//! temporary COW string object, optionally escapes it when the r1
//! selector is nonzero (the `'\\'` / 0x5c block the wrapper never
//! enables), converts it through [`crate::cxx::string_object`] +
//! `utf8_to_utf16_bounded` @ 0x082767fc into `dst + 2` bounded by the
//! 0xff-unit capacity, stores `utf16_code_unit_count_safe(dst + 2)` @
//! 0x08277164 into the result slot, and returns 0 — or `-0x32`
//! (`mvn r0,#0x31`) early when `src`, `dst + 2` or the capacity word is
//! NULL. The wrapper then publishes the low halfword of that count as the
//! u16 length prefix at `dst[0]` and returns the status verbatim.
//!
//! All five observed callers pass arg2 = 0 and a >=512-byte dst whose
//! first u16 is the length prefix and whose tail receives the code units
//! (e.g. `FUN_0805a8b4(auStack_218, 0, local_420)` @ 0x082a3830, which
//! then feeds `local_420 + 2` to `FUN_082765a8`).
//!
//! ## Deliberate deviations
//!
//! - The callee @ 0x0805ab44 remains a retailOS boundary behind the
//!   replaceable [`STRING_EXPORT_COUNTED_UTF16_IMPL`] seam. Device builds
//!   dispatch to its verified fixed address; the host default fails
//!   closed with `-0x32` (mirroring the callee's own NULL-argument error
//!   path, which likewise never touches the result slot), and tests
//!   install recorders.
//! - The stock result slot is the pushed-r3 spill: on the callee's error
//!   path it is never written, so `strh` publishes the caller's leftover
//!   r3 into `dst[0]`. The port zero-initializes the slot instead —
//!   reading an uninitialized stack word is not representable in safe
//!   codegen, and no observed caller inspects `dst[0]` after a nonzero
//!   status (every site gates on `status == 0`).

/// Verified load address of the unported conversion worker this wrapper
/// tail-sequences into.
pub const STRING_EXPORT_COUNTED_UTF16_IMPL_ADDRESS: usize = 0x0805_ab44;

/// The error status both the callee (`mvn r0,#0x31` @ 0x0805ab84) and the
/// fail-closed host default return.
pub const STRING_EXPORT_ERROR: i32 = -0x32;

/// Capacity the wrapper pins as stack arg 5: 0xff code units.
pub const COUNTED_UTF16_CAPACITY: u32 = 0xff;

/// The conversion worker @ 0x0805ab44: `(src, aux, dead, dst_units,
/// capacity, count_out) -> status`. `src` is the counted byte string,
/// `aux` selects the escape pass (wrapper always 0), `dead` is the
/// forwarded caller word the worker never reads, `dst_units` is
/// `dst + 2`, `capacity` is the 0xff bound, and `count_out` receives the
/// exported code-unit count on success.
pub type StringExportCountedUtf16Impl = unsafe extern "C" fn(
    src: *const u8,
    aux: u32,
    dead: u32,
    dst_units: *mut u16,
    capacity: u32,
    count_out: *mut u32,
) -> i32;

/// Boundary default for the worker. Device builds preserve the exact
/// retailOS call; host builds fail closed with [`STRING_EXPORT_ERROR`]
/// without touching the result slot, mirroring the worker's own
/// NULL-argument early return.
unsafe extern "C" fn firmware_string_export_counted_utf16_impl(
    src: *const u8,
    aux: u32,
    dead: u32,
    dst_units: *mut u16,
    capacity: u32,
    count_out: *mut u32,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let worker: StringExportCountedUtf16Impl =
            core::mem::transmute(STRING_EXPORT_COUNTED_UTF16_IMPL_ADDRESS);
        worker(src, aux, dead, dst_units, capacity, count_out)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = src;
        let _ = aux;
        let _ = dead;
        let _ = dst_units;
        let _ = capacity;
        let _ = count_out;

        STRING_EXPORT_ERROR
    }
}

/// Replaceable seam for the unported worker @ 0x0805ab44.
pub static mut STRING_EXPORT_COUNTED_UTF16_IMPL: StringExportCountedUtf16Impl =
    firmware_string_export_counted_utf16_impl;

#[inline(always)]
unsafe fn string_export_counted_utf16_impl_fn() -> StringExportCountedUtf16Impl {
    STRING_EXPORT_COUNTED_UTF16_IMPL
}

/// string_export_counted_utf16 — original: `FUN_0805a8b4` @ **0x0805a8b4**
/// (48 bytes; **5 unconditional `bl` call sites**; body issues 1 plain
/// `bl`, 0 predicated).
///
/// Exports the counted byte string `src` into `dst` as a length-prefixed
/// UTF-16 string: the worker fills `dst + 2` with at most
/// [`COUNTED_UTF16_CAPACITY`] code units and reports their count, which
/// this wrapper publishes as the u16 length prefix `dst[0]`. `dead` is
/// the original's r1: forwarded into the worker's never-read r2 to keep
/// the register stream identical. Returns the worker's status verbatim
/// (0 on success, [`STRING_EXPORT_ERROR`] on rejection).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_export_counted_utf16(
    src: *const u8,
    dead: u32,
    dst: *mut u16,
) -> i32 {
    let mut count: u32 = 0;
    let status = string_export_counted_utf16_impl_fn()(
        src,
        0,
        dead,
        dst.add(1),
        COUNTED_UTF16_CAPACITY,
        &mut count,
    );
    dst.write_volatile(count as u16);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::MutexGuard;

    static mut RECORD: Option<(usize, u32, u32, usize, u32, usize)> = None;
    static mut SLOT_WRITE: Option<u32> = None;
    static mut STATUS: i32 = 0;

    unsafe extern "C" fn recording_impl(
        src: *const u8,
        aux: u32,
        dead: u32,
        dst_units: *mut u16,
        capacity: u32,
        count_out: *mut u32,
    ) -> i32 {
        RECORD = Some((
            src as usize,
            aux,
            dead,
            dst_units as usize,
            capacity,
            count_out as usize,
        ));
        if let Some(value) = SLOT_WRITE {
            count_out.write(value);
        }
        STATUS
    }

    struct SeamGuard;
    impl SeamGuard {
        fn lock() -> (MutexGuard<'static, ()>, SeamGuard) {
            let guard = crate::testing::STRING_EXPORT_COUNTED_UTF16_TEST_LOCK
                .lock()
                .unwrap();
            unsafe {
                STRING_EXPORT_COUNTED_UTF16_IMPL = recording_impl;
                RECORD = None;
                SLOT_WRITE = None;
                STATUS = 0;
            }
            (guard, SeamGuard)
        }
    }
    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                STRING_EXPORT_COUNTED_UTF16_IMPL = firmware_string_export_counted_utf16_impl;
            }
        }
    }

    #[test]
    fn publishes_worker_count_as_u16_prefix() {
        let (_lock, _seam) = SeamGuard::lock();
        unsafe { SLOT_WRITE = Some(5) };

        let src: [u8; 8] = [3, 0, b'a', b'b', b'c', 0, 0, 0];
        let mut dst: [u16; 4] = [0xFFFF; 4];
        let status = unsafe {
            string_export_counted_utf16(src.as_ptr(), 0xDEAD_BEEF, dst.as_mut_ptr())
        };

        assert_eq!(status, 0, "status passes through verbatim");
        assert_eq!(dst[0], 5, "worker count becomes the u16 length prefix");
        let (src_seen, aux, dead, units, cap, slot) = unsafe { RECORD.unwrap() };
        assert_eq!(src_seen, src.as_ptr() as usize);
        assert_eq!(aux, 0, "wrapper pins the aux selector to 0");
        assert_eq!(dead, 0xDEAD_BEEF, "r1 forwards into the worker's dead r2");
        assert_eq!(
            units,
            unsafe { dst.as_ptr().add(1) } as usize,
            "worker receives dst + 2 bytes"
        );
        assert_eq!(cap, COUNTED_UTF16_CAPACITY, "capacity is pinned to 0xff");
        assert_ne!(slot, 0, "worker receives a live result slot");
    }

    #[test]
    fn truncates_count_to_low_halfword() {
        let (_lock, _seam) = SeamGuard::lock();
        unsafe { SLOT_WRITE = Some(0x1_0007) };

        let mut dst: [u16; 2] = [0xFFFF; 2];
        let status =
            unsafe { string_export_counted_utf16(core::ptr::null(), 0, dst.as_mut_ptr()) };

        assert_eq!(status, 0);
        assert_eq!(dst[0], 7, "strh keeps only the low 16 bits of the count");
    }

    #[test]
    fn error_path_still_stores_slot_and_returns_status() {
        let (_lock, _seam) = SeamGuard::lock();
        unsafe {
            SLOT_WRITE = None; // worker rejects: slot untouched
            STATUS = STRING_EXPORT_ERROR;
        }

        let mut dst: [u16; 2] = [0xFFFF; 2];
        let status =
            unsafe { string_export_counted_utf16(core::ptr::null(), 0, dst.as_mut_ptr()) };

        assert_eq!(status, STRING_EXPORT_ERROR, "error passes through verbatim");
        assert_eq!(
            dst[0], 0,
            "documented deviation: the port zero-initializes the slot stock \
             firmware leaves as the caller's spilled r3"
        );
    }

    #[test]
    fn host_default_seam_fails_closed() {
        let (_lock, _seam) = SeamGuard::lock();
        unsafe {
            STRING_EXPORT_COUNTED_UTF16_IMPL = firmware_string_export_counted_utf16_impl;
        }

        let mut dst: [u16; 2] = [0xFFFF; 2];
        let status =
            unsafe { string_export_counted_utf16(core::ptr::null(), 0, dst.as_mut_ptr()) };

        assert_eq!(status, STRING_EXPORT_ERROR);
        assert_eq!(dst[0], 0);
    }
}
