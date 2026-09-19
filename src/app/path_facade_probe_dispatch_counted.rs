//! Counted-string path dispatcher: probes a path through facade slot
//! +0x54, then selects facade slot +0x60 or +0x5c based on the probe's
//! flag byte.
//!
//! Port:
//! - [`path_facade_probe_dispatch_counted`] — original: `FUN_0805a84c` @
//!   **0x0805a84c** (104 bytes; **5 `bl` call sites**: 4 unconditional
//!   plain `bl` at 0x080aa620, 0x080bec64, 0x081a31d8, 0x081a4cbc and 1
//!   predicated `bleq` at 0x081a30dc, verified by decoding every ARM B/BL
//!   word in `osos.dec`; the body itself issues **4 plain `bl`s and 1
//!   conditional-branch-selected `bl`** — 5 `bl` instructions total,
//!   matching Ghidra's count). The next distinct function begins at
//!   0x0805a8b4 (`stmdb sp!,{r1-r5,lr}`, ported as
//!   [`crate::cxx::string_export_counted_utf16`]), confirming the
//!   104-byte extent.
//!
//! ## What it is
//!
//! Decoded from the raw ARM at 0x0805a84c (load base 0x08000000):
//!
//! ```text
//! 0805a84c  stmdb sp!, {r3,r4,r5,lr}  @ 4-byte frame; the pushed-r3
//!                                    @  spill slot is the probe's
//!                                    @  flag-byte out word
//! 0805a850  movs  r4, r0           @ counted string {u16 len @ +0,
//!                                  @  NUL-terminated bytes @ +2}
//! 0805a854  mvneq r0, #0x31        @ NULL -> -0x32
//! 0805a858  beq   0x0805a8b0       @   (early return)
//! 0805a85c  ldrh  r0, [r4,#0x0]    @ len prefix
//! 0805a860  mov   r1, sp           @ &flag_slot
//! 0805a864  mov   r2, r0, lsl #0x18
//! 0805a868  mov   r2, r2, asr #0x18@ hint = (i8)(len & 0xff)
//! 0805a86c  add   r0, r4, #0x2     @ path cstr = str + 2
//! 0805a870  bl    0x080891dc       @ probe = slot_54_from_cstr(path,
//!                                  @   &flag_slot, hint)
//! 0805a874  bl    0x0809da3c       @ map_status_code(probe)
//! 0805a878  cmp   r0, #0x0
//! 0805a87c  bne   0x0805a8b0       @ probe error -> return mapped
//! 0805a880  ldrb  r0, [sp,#0x0]    @ flag = slot & 0xff
//! 0805a884  cmp   r0, #0x0
//! 0805a888  ldrh  r0, [r4,#0x0]    @ reload len prefix
//! 0805a88c  mov   r1, r0, lsl #0x18
//! 0805a890  mov   r1, r1, asr #0x18@ hint = (i8)(len & 0xff)
//! 0805a894  add   r0, r4, #0x2     @ path cstr
//! 0805a898  beq   0x0805a8a4
//! 0805a89c  bl    0x080a8eb0       @ flag != 0: slot_60_from_cstr
//! 0805a8a0  b     0x0805a8a8
//! 0805a8a4  bl    0x08084d28       @ flag == 0: slot_5c_from_cstr
//! 0805a8a8  bl    0x0809da3c       @ map_status_code(op)
//! 0805a8ac  cmp   r0, #0x0         @ sets flags for the shared
//! 0805a8b0  ldmia sp!, {r3,r4,r5,pc}  @ epilogue; r0 = result
//! ```
//!
//! The argument is the same counted byte string layout
//! [`crate::cxx::string_export_counted_utf16`] consumes: a u16 length
//! prefix at +0 followed by a NUL-terminated C string at +2. Both the
//! probe and the selected facade operation receive the sign-extended low
//! byte of that prefix as their `base_hint` argument — not the string
//! length semantics the prefix carries elsewhere.
//!
//! The probe @ 0x080891dc constructs a path object from the cstr
//! (`path_object_construct` @ 0x08279284), builds an interface guard
//! with `hint` as the base selector (@ 0x08089214), dispatches facade
//! vtable slot **+0x54** `(facade, path_object, &flag_slot)`, destroys
//! the object (@ 0x082792fc veneer) and returns the dispatch status.
//! The selected operation @ 0x080a8eb0 is the slot **+0x60** twin of the
//! ported [`crate::app::path_probe::path_facade_slot_5c_from_cstr`]
//! (0x08084d28): construct path object, guarded facade slot +0x60
//! dispatch, destroy. The +0x54 probe's flag byte chooses between them;
//! the concrete semantic identity of slots +0x54/+0x5c/+0x60 remains
//! unresolved, so the structural names are kept.
//!
//! ## RetailOS boundary
//!
//! The slot +0x60 wrapper @ 0x080a8eb0 remains a retailOS boundary behind
//! the replaceable [`PATH_FACADE_SLOT_60_FROM_CSTR_IMPL`] seam. The slot
//! +0x54 probe @ 0x080891dc is now the ported
//! [`crate::app::path_probe::path_facade_slot_54_from_cstr`]; its seam is
//! retained only so this caller's host tests can record probe results. The
//! slot +0x5c wrapper @ 0x08084d28 and `map_status_code` @ 0x0809da3c are
//! already ported and are called directly.
//!
//! ## Deliberate deviations
//!
//! - The stock flag slot is the pushed-r3 spill, never initialized
//!   before the probe call: if the probe returns 0 without writing the
//!   slot, `ldrb` samples the caller's leftover r3. The port
//!   zero-initializes the slot — reading an uninitialized stack word is
//!   not representable in safe codegen — which is also the value every
//!   successful probe observed in callers establishes.

/// Load address of the ported facade slot +0x54 cstr probe
/// (`FUN_080891dc`).
pub const PATH_FACADE_SLOT_54_FROM_CSTR_ADDRESS: usize = 0x0808_91dc;

/// Verified load address of the unported facade slot +0x60 cstr wrapper
/// (`FUN_080a8eb0`).
pub const PATH_FACADE_SLOT_60_FROM_CSTR_ADDRESS: usize = 0x080a_8eb0;

/// The error status the wrapper returns for a NULL counted string
/// (`mvn r0,#0x31` @ 0x0805a854) and both fail-closed host defaults
/// return.
pub const PROBE_DISPATCH_ERROR: i32 = -0x32;

/// The probe @ 0x080891dc: `(path, flag_out, base_hint) -> status`.
/// `path` is the NUL-terminated cstr at counted-string +2; `flag_out`
/// receives the flag word whose low byte selects the follow-up
/// operation; `base_hint` is the sign-extended low byte of the counted
/// string's u16 prefix.
pub type PathFacadeSlot54FromCstr =
    unsafe extern "C" fn(path: *const u8, flag_out: *mut u32, base_hint: u32) -> i32;

/// The slot +0x60 wrapper @ 0x080a8eb0: `(path, base_hint) -> status`,
/// ABI-identical to the ported slot +0x5c twin.
pub type PathFacadeSlot60FromCstr =
    unsafe extern "C" fn(path: *const u8, base_hint: u32) -> i32;


/// Boundary default for the slot +0x60 wrapper, same fail-closed policy
/// as the probe default.
unsafe extern "C" fn firmware_path_facade_slot_60_from_cstr(
    path: *const u8,
    base_hint: u32,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let wrapper: PathFacadeSlot60FromCstr =
            core::mem::transmute(PATH_FACADE_SLOT_60_FROM_CSTR_ADDRESS);
        wrapper(path, base_hint)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = path;
        let _ = base_hint;

        PROBE_DISPATCH_ERROR
    }
}

/// Replaceable seam for the ported probe @ 0x080891dc.
pub static mut PATH_FACADE_SLOT_54_FROM_CSTR_IMPL: PathFacadeSlot54FromCstr =
    crate::app::path_probe::path_facade_slot_54_from_cstr;

/// Replaceable seam for the unported slot +0x60 wrapper @ 0x080a8eb0.
pub static mut PATH_FACADE_SLOT_60_FROM_CSTR_IMPL: PathFacadeSlot60FromCstr =
    firmware_path_facade_slot_60_from_cstr;

#[inline(always)]
unsafe fn path_facade_slot_54_from_cstr_fn() -> PathFacadeSlot54FromCstr {
    PATH_FACADE_SLOT_54_FROM_CSTR_IMPL
}

#[inline(always)]
unsafe fn path_facade_slot_60_from_cstr_fn() -> PathFacadeSlot60FromCstr {
    PATH_FACADE_SLOT_60_FROM_CSTR_IMPL
}

/// path_facade_probe_dispatch_counted — original: `FUN_0805a84c` @
/// **0x0805a84c** (104 bytes; **5 `bl` call sites**: 4 unconditional, 1
/// `bleq`; body issues 5 `bl` instructions, 0 predicated).
///
/// Rejects a NULL `counted_path` with [`PROBE_DISPATCH_ERROR`].
/// Otherwise probes the cstr at `counted_path + 2` through facade slot
/// +0x54 with `base_hint = (i8)(*(u16 *)counted_path & 0xff)`, returns
/// the mapped probe status on failure, then reads the probe's flag byte:
/// nonzero dispatches facade slot +0x60, zero dispatches the ported
/// facade slot +0x5c wrapper, and the selected operation's status is
/// returned through `map_status_code`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_facade_probe_dispatch_counted(
    counted_path: *const u8,
) -> i32 {
    if counted_path.is_null() {
        return PROBE_DISPATCH_ERROR;
    }

    let base_hint = (*(counted_path as *const u16) as u8) as i8 as i32 as u32;
    let path = counted_path.add(2);

    let mut flag: u32 = 0;
    let probe = path_facade_slot_54_from_cstr_fn()(path, &mut flag, base_hint);
    let status = crate::util::status_code_map::map_status_code(probe);
    if status != 0 {
        return status;
    }

    let base_hint = (*(counted_path as *const u16) as u8) as i8 as i32 as u32;
    let op = if flag as u8 != 0 {
        path_facade_slot_60_from_cstr_fn()(path, base_hint)
    } else {
        crate::app::path_probe::path_facade_slot_5c_from_cstr(path, base_hint) as i32
    };
    crate::util::status_code_map::map_status_code(op)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::MutexGuard;

    static mut PROBE_RECORD: Option<(usize, usize, u32)> = None;
    static mut PROBE_FLAG_WRITE: Option<u32> = None;
    static mut PROBE_STATUS: i32 = 0;
    static mut SLOT_60_RECORD: Option<(usize, u32)> = None;
    static mut SLOT_60_STATUS: i32 = 0;

    unsafe extern "C" fn recording_probe(
        path: *const u8,
        flag_out: *mut u32,
        base_hint: u32,
    ) -> i32 {
        PROBE_RECORD = Some((path as usize, flag_out as usize, base_hint));
        if let Some(value) = PROBE_FLAG_WRITE {
            flag_out.write(value);
        }
        PROBE_STATUS
    }

    unsafe extern "C" fn recording_slot_60(path: *const u8, base_hint: u32) -> i32 {
        SLOT_60_RECORD = Some((path as usize, base_hint));
        SLOT_60_STATUS
    }

    struct SeamGuard;
    impl SeamGuard {
        fn lock() -> (MutexGuard<'static, ()>, SeamGuard) {
            let guard = crate::testing::PATH_FACADE_PROBE_DISPATCH_COUNTED_TEST_LOCK
                .lock()
                .unwrap();
            unsafe {
                PATH_FACADE_SLOT_54_FROM_CSTR_IMPL = recording_probe;
                PATH_FACADE_SLOT_60_FROM_CSTR_IMPL = recording_slot_60;
                PROBE_RECORD = None;
                PROBE_FLAG_WRITE = None;
                PROBE_STATUS = 0;
                SLOT_60_RECORD = None;
                SLOT_60_STATUS = 0;
            }
            (guard, SeamGuard)
        }
    }
    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                PATH_FACADE_SLOT_54_FROM_CSTR_IMPL =
                    crate::app::path_probe::path_facade_slot_54_from_cstr;
                PATH_FACADE_SLOT_60_FROM_CSTR_IMPL = firmware_path_facade_slot_60_from_cstr;
            }
        }
    }

    /// {u16 len = 3, "abc\0"} counted string fixture.
    const COUNTED: [u8; 8] = [3, 0, b'a', b'b', b'c', 0, 0, 0];

    #[test]
    fn null_counted_string_fails_closed_without_probing() {
        let (_lock, _seam) = SeamGuard::lock();

        let status = unsafe { path_facade_probe_dispatch_counted(core::ptr::null()) };

        assert_eq!(status, PROBE_DISPATCH_ERROR, "mvn r0,#0x31 = -0x32");
        assert!(unsafe { PROBE_RECORD.is_none() }, "NULL never reaches the probe");
        assert!(unsafe { SLOT_60_RECORD.is_none() });
    }

    #[test]
    fn probe_error_returns_mapped_status_and_skips_dispatch() {
        let (_lock, _seam) = SeamGuard::lock();
        unsafe { PROBE_STATUS = 2 };

        let status = unsafe { path_facade_probe_dispatch_counted(COUNTED.as_ptr()) };

        assert_eq!(status, -34, "map_status_code(2) = -34 passes back verbatim");
        assert!(unsafe { SLOT_60_RECORD.is_none() }, "no facade op on probe error");
    }

    #[test]
    fn probe_receives_cstr_and_sign_extended_low_byte_hint() {
        let (_lock, _seam) = SeamGuard::lock();
        // u16 prefix 0x00ff -> (i8)0xff = -1 -> 0xffffffff hint.
        let counted: [u8; 8] = [0xff, 0x00, b'x', 0, 0, 0, 0, 0];
        unsafe { PROBE_STATUS = 5 }; // mapped to -38: stop after the probe

        let status = unsafe { path_facade_probe_dispatch_counted(counted.as_ptr()) };

        assert_eq!(status, -38);
        let (path, flag_out, hint) = unsafe { PROBE_RECORD.unwrap() };
        assert_eq!(path, unsafe { counted.as_ptr().add(2) } as usize);
        assert_ne!(flag_out, 0, "probe receives a live flag slot");
        assert_eq!(hint, 0xffff_ffff, "hint sign-extends the low prefix byte");
    }

    #[test]
    fn flag_clear_selects_slot_5c_and_maps_status() {
        let (_lock, _seam) = SeamGuard::lock();
        unsafe { PROBE_FLAG_WRITE = Some(0x100) }; // low byte 0

        let status = unsafe { path_facade_probe_dispatch_counted(COUNTED.as_ptr()) };

        assert!(unsafe { SLOT_60_RECORD.is_none() }, "flag 0 never reaches slot +0x60");
        // The ported slot_5c chain is total on host and fails closed to
        // 0 ("does not exist"); map_status_code(0) = 0.
        assert_eq!(status, 0);
    }

    #[test]
    fn flag_set_selects_slot_60_with_matching_args() {
        let (_lock, _seam) = SeamGuard::lock();
        unsafe {
            PROBE_FLAG_WRITE = Some(1);
            SLOT_60_STATUS = 7; // map_status_code(7) = -42
        };

        let status = unsafe { path_facade_probe_dispatch_counted(COUNTED.as_ptr()) };

        assert_eq!(status, -42, "selected op status is mapped on return");
        let (path, hint) = unsafe { SLOT_60_RECORD.unwrap() };
        assert_eq!(path, unsafe { COUNTED.as_ptr().add(2) } as usize);
        assert_eq!(hint, 3, "counted prefix 3 reaches the op as the hint");
    }

    #[test]
    fn host_default_seams_fail_closed() {
        let (_lock, _seam) = SeamGuard::lock();
        unsafe {
            PATH_FACADE_SLOT_54_FROM_CSTR_IMPL =
                crate::app::path_probe::path_facade_slot_54_from_cstr;
            PATH_FACADE_SLOT_60_FROM_CSTR_IMPL = firmware_path_facade_slot_60_from_cstr;
        }

        let status = unsafe { path_facade_probe_dispatch_counted(COUNTED.as_ptr()) };

        assert_eq!(status, 0, "the ported probe's host facade slot fails closed");
    }

    use crate::util::status_code_map::map_status_code;
}
