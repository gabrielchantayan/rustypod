//! Sub-record reference chase for the retailOS record query engine.

/// Typed-value tag: inline u32 payload at descriptor `+4`, continuation
/// pointer at descriptor `+8`.
const TAG_INLINE_WORD: i16 = 3;
/// Typed-value tag with the same inline layout as [`TAG_INLINE_WORD`].
const TAG_INLINE_WORD_ALT: i16 = 4;
/// Typed-value tag: unaligned u32 payload at descriptor `+0xa`,
/// continuation pointer at descriptor `+0xe`.
const TAG_UNALIGNED_WORD: i16 = 0x300;
/// Typed-value tag with the same unaligned layout as
/// [`TAG_UNALIGNED_WORD`].
const TAG_UNALIGNED_WORD_ALT: i16 = 0x400;

type QueryDispatch = unsafe extern "C" fn(
    object: *mut u8,
    kind: u32,
    word2: *const u8,
    word3: u32,
    key: *const u8,
    descriptor: *const u8,
    detail: u32,
) -> i32;

/// Calls the stock query-dispatch helper, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x0805c0c8. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original reads the object tag halfword at
/// `+2`, notes whether it is 0x482b for 0x080433b0, then forwards all
/// seven arguments through the method pointer at `object + 0x158` via
/// 0x08065dfc and remaps status 0x20 to 0x30.
unsafe extern "C" fn firmware_query_dispatch(
    object: *mut u8,
    kind: u32,
    word2: *const u8,
    word3: u32,
    key: *const u8,
    descriptor: *const u8,
    detail: u32,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let dispatch: QueryDispatch = core::mem::transmute(0x0805_c0c8usize);
        dispatch(object, kind, word2, word3, key, descriptor, detail)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = (object, kind, word2, word3, key, descriptor, detail);
        // A nonzero status keeps host callers on the untouched failure path.
        -1
    }
}

/// Narrow boundary for the unported 0x0805c0c8 dependency.
static mut QUERY_DISPATCH: QueryDispatch = firmware_query_dispatch;

#[inline(always)]
unsafe fn query_dispatch_fn() -> QueryDispatch {
    core::ptr::read_volatile(core::ptr::addr_of!(QUERY_DISPATCH))
}

/// sub_record_lookup — original: `FUN_0805be98` @ `0x0805be98` (136 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/004/0805be98_FUN_0805be98.c`;
/// assembly: `decomp/osos.asm` @ `0x0805be98..0x0805bf1c`.
///
/// Runs the stock query-dispatch helper 0x0805c0c8 with all seven
/// arguments forwarded unchanged and returns its status when nonzero.
/// On a zero status it interprets `descriptor` as a typed-value header:
/// the signed halfword tag at `+0` selects the payload layout — tags 3
/// and 4 carry an inline u32 at `+4` with a continuation pointer at `+8`
/// (`ldreq r0,[r4,#4]; addeq r12,r4,#8`), tags 0x300 and 0x400 carry an
/// unaligned u32 at `+0xa` read through the ported
/// [`crate::libc::rt_unaligned::__rt_uread4`] (0x08031140) with the
/// continuation at `+0xe`. Any other tag, or a zero payload, yields a
/// zero return. A nonzero payload is chased with a second dispatch of
/// `(object, payload, continuation, 0, key, descriptor, detail)` and its
/// status is returned. Callers treat 0x37 as "not here, keep searching"
/// (see `FUN_0805bfd0`), so this is the query engine's sub-record
/// reference chase: resolve one level of indirection out of the typed
/// value the first query left in `descriptor`.
///
/// The true 136-byte extent ends at `pop {...,pc}` @ 0x0805bf1c; the next
/// function starts at 0x0805bf20. Decoding the disassembly finds exactly
/// five inbound calls, all plain unconditional `bl` (0x08051838,
/// 0x0805c024, 0x0805d58c, 0x0805d660, 0x0806ca90); there are no
/// predicated callers. The body itself issues three `bl`s — two to the
/// dispatch helper 0x0805c0c8 and one to __rt_uread4.
///
/// Deviations: none in behavior. The dispatch helper stays in retailOS
/// behind the [`QUERY_DISPATCH`] boundary — the ARM build therefore calls
/// it as `blx` through the volatile seam pointer instead of the
/// original's direct `bl 0x0805c0c8`, and LLVM turns the second dispatch
/// into a tail call. LLVM also inlines the ported __rt_uread4 byte-wise
/// instead of issuing the original's `bl 0x08031140`, and uses an
/// unsigned `ldrh`/`sub`/`bcc` range test for tags 3/4 that is equivalent
/// to the original's signed compares for every i16 tag value.
///
/// # Safety
///
/// Like the original, there is no null guard on `descriptor` on the
/// success path: it must be readable for at least 0xe bytes (tag at `+0`,
/// words at `+4`/`+0xa`). `object` must be valid for the stock dispatch
/// helper, which dereferences `+2` and `+0x158`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sub_record_lookup(
    object: *mut u8,
    kind: u32,
    word2: *const u8,
    word3: u32,
    key: *const u8,
    descriptor: *const u8,
    detail: u32,
) -> i32 {
    let dispatch = query_dispatch_fn();
    let mut status = dispatch(object, kind, word2, word3, key, descriptor, detail);
    if status == 0 {
        let tag = (descriptor as *const i16).read();
        let (payload, continuation) = if tag == TAG_INLINE_WORD || tag == TAG_INLINE_WORD_ALT {
            (
                (descriptor.add(4) as *const u32).read(),
                descriptor.add(8),
            )
        } else if tag == TAG_UNALIGNED_WORD || tag == TAG_UNALIGNED_WORD_ALT {
            (
                crate::libc::rt_unaligned::__rt_uread4(descriptor.add(0xa)),
                descriptor.add(0xe),
            )
        } else {
            return 0;
        };
        if payload != 0 {
            status = dispatch(object, payload, continuation, 0, key, descriptor, detail);
        }
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct DispatchCall {
        object: usize,
        kind: u32,
        word2: usize,
        word3: u32,
        key: usize,
        descriptor: usize,
        detail: u32,
    }

    static mut DISPATCH_LOG: Vec<DispatchCall> = Vec::new();
    static mut DISPATCH_STATUSES: Vec<i32> = Vec::new();

    unsafe extern "C" fn recording_query_dispatch(
        object: *mut u8,
        kind: u32,
        word2: *const u8,
        word3: u32,
        key: *const u8,
        descriptor: *const u8,
        detail: u32,
    ) -> i32 {
        let log = &mut *core::ptr::addr_of_mut!(DISPATCH_LOG);
        let statuses = &*core::ptr::addr_of!(DISPATCH_STATUSES);
        log.push(DispatchCall {
            object: object as usize,
            kind,
            word2: word2 as usize,
            word3,
            key: key as usize,
            descriptor: descriptor as usize,
            detail,
        });
        statuses
            .get(log.len() - 1)
            .copied()
            .unwrap_or(0)
    }

    /// Restores the stock-call boundary before another test uses it.
    struct DispatchReset;

    impl Drop for DispatchReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(QUERY_DISPATCH).write(firmware_query_dispatch);
            }
        }
    }

    struct DispatchMocks {
        _guard: MutexGuard<'static, ()>,
        _reset: DispatchReset,
    }

    fn install_dispatch_mocks(statuses: &[i32]) -> DispatchMocks {
        let guard = DISPATCH_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(DISPATCH_LOG)).clear();
            let slot = &mut *core::ptr::addr_of_mut!(DISPATCH_STATUSES);
            slot.clear();
            slot.extend_from_slice(statuses);
            core::ptr::addr_of_mut!(QUERY_DISPATCH).write(recording_query_dispatch);
        }
        DispatchMocks {
            _guard: guard,
            _reset: DispatchReset,
        }
    }

    fn dispatch_log() -> Vec<DispatchCall> {
        unsafe { (*core::ptr::addr_of!(DISPATCH_LOG)).clone() }
    }

    /// Builds a 16-byte descriptor: i16 tag at +0, u32 payload at +4.
    fn inline_descriptor(tag: i16, payload: u32) -> [u8; 16] {
        let mut d = [0u8; 16];
        d[0..2].copy_from_slice(&tag.to_le_bytes());
        d[4..8].copy_from_slice(&payload.to_le_bytes());
        d
    }

    /// Builds a 20-byte descriptor: i16 tag at +0, unaligned u32 payload
    /// at +0xa.
    fn unaligned_descriptor(tag: i16, payload: u32) -> [u8; 20] {
        let mut d = [0u8; 20];
        d[0..2].copy_from_slice(&tag.to_le_bytes());
        d[0xa..0xe].copy_from_slice(&payload.to_le_bytes());
        d
    }

    #[test]
    fn nonzero_initial_status_short_circuits() {
        let _mocks = install_dispatch_mocks(&[0x37]);
        let d = inline_descriptor(3, 0xdead_beef);
        let mut object = [0u8; 8];
        let status =
            unsafe { sub_record_lookup(object.as_mut_ptr(), 7, 9 as *const u8, 3, 11 as *const u8, d.as_ptr(), 0x55) };
        assert_eq!(status, 0x37, "the first dispatch status passes through");
        let log = dispatch_log();
        assert_eq!(log.len(), 1, "no chase happens on a nonzero status");
        assert_eq!(
            log[0],
            DispatchCall {
                object: object.as_mut_ptr() as usize,
                kind: 7,
                word2: 9,
                word3: 3,
                key: 11,
                descriptor: d.as_ptr() as usize,
                detail: 0x55,
            },
            "all seven arguments forward unchanged"
        );
    }

    #[test]
    fn tag_3_chases_inline_payload() {
        let _mocks = install_dispatch_mocks(&[0, 0x21]);
        let d = inline_descriptor(3, 0x1122_3344);
        let mut object = [0u8; 8];
        let status = unsafe {
            sub_record_lookup(object.as_mut_ptr(), 7, core::ptr::null(), 0, 11 as *const u8, d.as_ptr(), 0x55)
        };
        assert_eq!(status, 0x21, "the chase dispatch status is returned");
        let log = dispatch_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].kind, 0x1122_3344, "payload from descriptor +4");
        assert_eq!(
            log[1].word2,
            d.as_ptr() as usize + 8,
            "continuation pointer is descriptor +8"
        );
        assert_eq!(log[1].word3, 0, "the chase zeroes word3");
        assert_eq!(log[1].key, 11, "key forwards unchanged");
        assert_eq!(log[1].descriptor, d.as_ptr() as usize);
        assert_eq!(log[1].detail, 0x55);
    }

    #[test]
    fn tag_4_uses_the_same_inline_layout() {
        let _mocks = install_dispatch_mocks(&[0, 0]);
        let d = inline_descriptor(4, 0xabcd);
        let mut object = [0u8; 8];
        let status = unsafe {
            sub_record_lookup(object.as_mut_ptr(), 0, core::ptr::null(), 0, core::ptr::null(), d.as_ptr(), 0)
        };
        assert_eq!(status, 0);
        let log = dispatch_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].kind, 0xabcd);
        assert_eq!(log[1].word2, d.as_ptr() as usize + 8);
    }

    #[test]
    fn tag_0x300_chases_unaligned_payload() {
        let _mocks = install_dispatch_mocks(&[0, 0x30]);
        let d = unaligned_descriptor(0x300, 0x5566_7788);
        let mut object = [0u8; 8];
        let status = unsafe {
            sub_record_lookup(object.as_mut_ptr(), 0, core::ptr::null(), 0, core::ptr::null(), d.as_ptr(), 0)
        };
        assert_eq!(status, 0x30);
        let log = dispatch_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].kind, 0x5566_7788, "payload from descriptor +0xa");
        assert_eq!(
            log[1].word2,
            d.as_ptr() as usize + 0xe,
            "continuation pointer is descriptor +0xe"
        );
    }

    #[test]
    fn tag_0x400_uses_the_same_unaligned_layout() {
        let _mocks = install_dispatch_mocks(&[0, 0]);
        let d = unaligned_descriptor(0x400, 1);
        let mut object = [0u8; 8];
        let status = unsafe {
            sub_record_lookup(object.as_mut_ptr(), 0, core::ptr::null(), 0, core::ptr::null(), d.as_ptr(), 0)
        };
        assert_eq!(status, 0);
        let log = dispatch_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].kind, 1);
        assert_eq!(log[1].word2, d.as_ptr() as usize + 0xe);
    }

    #[test]
    fn unknown_tag_returns_zero_without_chasing() {
        let _mocks = install_dispatch_mocks(&[0]);
        let d = inline_descriptor(5, 0xdead_beef);
        let mut object = [0u8; 8];
        let status = unsafe {
            sub_record_lookup(object.as_mut_ptr(), 0, core::ptr::null(), 0, core::ptr::null(), d.as_ptr(), 0)
        };
        assert_eq!(status, 0, "an unrecognized tag yields a zero return");
        assert_eq!(dispatch_log().len(), 1, "no second dispatch runs");
    }

    #[test]
    fn zero_payload_returns_zero_without_chasing() {
        let _mocks = install_dispatch_mocks(&[0]);
        let d = inline_descriptor(3, 0);
        let mut object = [0u8; 8];
        let status = unsafe {
            sub_record_lookup(object.as_mut_ptr(), 0, core::ptr::null(), 0, core::ptr::null(), d.as_ptr(), 0)
        };
        assert_eq!(status, 0, "a zero payload yields a zero return");
        assert_eq!(dispatch_log().len(), 1, "no second dispatch runs");
    }
}
