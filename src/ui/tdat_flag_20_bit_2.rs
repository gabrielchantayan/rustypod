//! Setter for bit 2 of the 'tdat' UI-element flag byte at +0x20, with
//! refcount coupling.
//!
//! - `tdat_element_set_flag_20_bit_2` — original: `FUN_08067b4c` @
//!   `0x08067b4c` (108 bytes including the literal-pool word @
//!   `0x08067bb4`; 14 `bl` call sites: 12 unconditional + 2 `blne`, plus
//!   3 predicated tail `b` branches).

use core::ptr;

use super::tdat_class_check::ui_element_is_tdat_class;

/// Byte offset of the flag byte the setter reads and rewrites
/// (`ldrbne r0, [r4, #0x20]` / `strb r0, [r4, #0x20]`).
const FLAG_BYTE_OFFSET: usize = 0x20;

/// Bit 2 of the flag byte (`mov r1, #4` / `and r1, r1, r2, lsl #2` /
/// `bic r0, r0, #4` / `orr r0, r0, r1`).
const FLAG_BIT: u32 = 4;

/// Byte offset of the tagged-handler list head handed to the notify
/// callee on the enable path (`add r0, r4, #0x54`).
const TAGGED_LIST_OFFSET: usize = 0x54;

/// Event key passed to the tagged-list notify on the enable path:
/// literal-pool word @ `0x08067bb4`, the value 0x74646472 ('t','d','d','r'
/// MSB to LSB; bytes 'r','d','d','t' little-endian). Sibling refcounts
/// pass 0x74647274 ('tdrt') on first retain and 0x7464726c ('tdrl') on
/// last release to the virtual handler at element+0x4c.
const ENABLE_NOTIFY_TAG: u32 = 0x7464_6472;

/// ABI of the still-unported 'tdat' element refcount ops:
/// release @ `0x0806aa64` (decrements the halfword at element+0x40,
/// firing the virtual handler at +0x4c with the 'tdrl' key when it hits
/// zero) and addref @ `0x0806aaac` (increments it, firing 'tdrt' on the
/// 0 -> 1 transition).
pub type TdatRefcountOp = unsafe extern "C" fn(*mut u8) -> u32;

/// ABI of the still-unported tagged-handler list walker @ `0x08066bb8`:
/// (list head, event key, context, flags, stack arg).
pub type TdatTaggedListNotify =
    unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tdat_refcount_release(element: *mut u8) -> u32 {
    let release: TdatRefcountOp = core::mem::transmute(0x0806_aa64usize);
    release(element)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_tdat_refcount_release(_element: *mut u8) -> u32 {
    0
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tdat_refcount_addref(element: *mut u8) -> u32 {
    let addref: TdatRefcountOp = core::mem::transmute(0x0806_aaacusize);
    addref(element)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_tdat_refcount_addref(_element: *mut u8) -> u32 {
    0
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tdat_tagged_list_notify(
    list: *mut u8,
    tag: u32,
    context: *mut u8,
    flags: u32,
    stack_arg: u32,
) -> u32 {
    let notify: TdatTaggedListNotify = core::mem::transmute(0x0806_6bb8usize);
    notify(list, tag, context, flags, stack_arg)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_tdat_tagged_list_notify(
    _list: *mut u8,
    _tag: u32,
    _context: *mut u8,
    _flags: u32,
    _stack_arg: u32,
) -> u32 {
    0
}

/// Calls outside this one-function port.
///
/// Target builds dispatch to the unported refcount ops at `0x0806aa64` /
/// `0x0806aaac` and the tagged-list walker at `0x08066bb8`. Host tests
/// replace this boundary to observe the original call pattern.
#[derive(Clone, Copy)]
pub struct TdatFlag20Ops {
    pub refcount_release: TdatRefcountOp,
    pub refcount_addref: TdatRefcountOp,
    pub tagged_list_notify: TdatTaggedListNotify,
}

/// Production dispatch boundary for the three unported callees.
pub const DEFAULT_TDAT_FLAG_20_OPS: TdatFlag20Ops = TdatFlag20Ops {
    refcount_release: retail_tdat_refcount_release,
    refcount_addref: retail_tdat_refcount_addref,
    tagged_list_notify: retail_tdat_tagged_list_notify,
};

/// Active dispatch boundary.
///
/// This is intentionally a seam: none of `0x0806aa64`, `0x0806aaac` and
/// `0x08066bb8` has a `ported` ledger entry, whereas the class predicate
/// dependency is the existing Rust port at `0x0806aa3c`.
pub static mut TDAT_FLAG_20_OPS: TdatFlag20Ops = DEFAULT_TDAT_FLAG_20_OPS;

#[inline(always)]
fn tdat_flag_20_ops() -> TdatFlag20Ops {
    unsafe { ptr::read_volatile(ptr::addr_of!(TDAT_FLAG_20_OPS)) }
}

/// tdat_element_set_flag_20_bit_2 — original: `FUN_08067b4c` @
/// `0x08067b4c` (108 bytes).
///
/// Assembly decoded from `work/firmware/osos.dec` @
/// `0x08067b4c..0x08067bb8`:
///
/// ```text
/// 08067b4c  push {r3, r4, r5, lr}
/// 08067b50  mov r4, r0
/// 08067b54  mov r2, r1
/// 08067b58  bl 0x0806aa3c        ; ui_element_is_tdat_class
/// 08067b5c  cmp r0, #0
/// 08067b60  ldrbne r0, [r4, #0x20]
/// 08067b64  lslne r1, r0, #29
/// 08067b68  cmpne r2, r1, lsr #31
/// 08067b6c  beq 0x08067bb0       ; no change: return flags
/// 08067b70  mov r1, #4
/// 08067b74  and r1, r1, r2, lsl #2
/// 08067b78  bic r0, r0, #4
/// 08067b7c  orr r0, r0, r1
/// 08067b80  strb r0, [r4, #0x20]
/// 08067b84  cmp r2, #0
/// 08067b88  mov r0, r4
/// 08067b8c  popeq {r3, r4, r5, lr}
/// 08067b90  beq 0x0806aa64       ; tail: refcount release
/// 08067b94  bl 0x0806aaac        ; refcount addref (result discarded)
/// 08067b98  mov r3, #0
/// 08067b9c  ldr r1, [pc, #0x10]  ; = 0x74646472 @ 0x08067bb4
/// 08067ba0  mov r2, r4
/// 08067ba4  add r0, r4, #0x54
/// 08067ba8  str r3, [sp]
/// 08067bac  bl 0x08066bb8        ; tagged-list notify
/// 08067bb0  pop {r3, r4, r5, pc}
/// 08067bb4  .word 0x74646472
/// ```
///
/// Ghidra reports 172 bytes; the true extent is 108 — the next function
/// (a two-field setter, `str r1,[r0,#0x4c]; str r2,[r0,#0x50]; bx lr`)
/// starts at `0x08067bb8`, and Ghidra's extent swallows it plus the head
/// of the `push {r4, r5, r6, lr}` function at `0x08067bc4`. Call count
/// verified by decoding every B/BL word in osos.dec: 14 `bl` (12
/// unconditional, 2 `blne` @ `0x0805d3c8` / `0x0806ce10`) plus 3
/// predicated tail branches (`bne` @ `0x0805d338`, `bne` @ `0x0805d360`,
/// `beq` @ `0x0805d390`). The predicated sites gate the call on their
/// own state — this function has NO NULL guard of its own: when the
/// class check fails (NULL included) the byte store at element+0x20
/// still happens with the old flags treated as 0.
///
/// Algorithm: if `element` passes the 'tdat' class check, load the flag
/// byte at +0x20 and return it unchanged when `value` already equals its
/// bit 2 (exact u32 compare against 0/1). Otherwise rewrite the byte as
/// `(flags & !4) | ((value << 2) & 4)` — only bit 0 of `value` reaches
/// the byte; all other bits of the old byte are preserved. When `value`
/// is zero, tail-call the refcount release @ `0x0806aa64` and return its
/// result. Otherwise call the refcount addref @ `0x0806aaac` (result
/// discarded), then walk the tagged-handler list at element+0x54 with
/// the event key 0x74646472, the element as context, and zeroed flag /
/// stack arguments, returning the walker's result. Early return yields
/// the flag byte.
///
/// Deliberate deviations: the three callees `0x0806aa64`, `0x0806aaac`
/// and `0x08066bb8` are not ported, so their calls go through the
/// `TDAT_FLAG_20_OPS` dispatch seam (target defaults transmute the stock
/// addresses). The already-ported `ui_element_is_tdat_class` is called
/// directly instead of branching to stock `0x0806aa3c`.
///
/// # Safety
///
/// `element` must be non-NULL and writable through offset +0x20: the
/// original stores the rewritten flag byte even when the class check
/// fails, so a NULL or foreign pointer faults exactly like stock. On the
/// enable path the seam receives element+0x54, so the object must be at
/// least 0x58 bytes for the retail walker to operate on it.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tdat_element_set_flag_20_bit_2")]
#[inline(never)]
pub unsafe extern "C" fn tdat_element_set_flag_20_bit_2(element: *mut u8, value: u32) -> u32 {
    let mut flags: u32 = 0;
    if ui_element_is_tdat_class(element) != 0 {
        flags = u32::from(element.add(FLAG_BYTE_OFFSET).read());
        if value == (flags >> 2) & 1 {
            return flags;
        }
    }

    let flags = (flags & !FLAG_BIT) | ((value << 2) & FLAG_BIT);
    element.add(FLAG_BYTE_OFFSET).write(flags as u8);

    if value == 0 {
        return (tdat_flag_20_ops().refcount_release)(element);
    }
    (tdat_flag_20_ops().refcount_addref)(element);
    (tdat_flag_20_ops().tagged_list_notify)(
        element.add(TAGGED_LIST_OFFSET),
        ENABLE_NOTIFY_TAG,
        element,
        0,
        0,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    const TDAT_CLASS_TAG: u32 = 0x7464_6174;
    const OTHER_TAG: u32 = 0x706c_7374;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASE_CALLS: u32 = 0;
    static mut ADDREF_CALLS: u32 = 0;
    static mut NOTIFY_CALLS: u32 = 0;
    static mut RELEASE_ELEMENT: usize = 0;
    static mut ADDREF_ELEMENT: usize = 0;
    static mut NOTIFY_LIST: usize = 0;
    static mut NOTIFY_TAG: u32 = 0;
    static mut NOTIFY_CONTEXT: usize = 0;
    static mut NOTIFY_FLAGS: u32 = u32::MAX;
    static mut NOTIFY_STACK: u32 = u32::MAX;
    static mut RELEASE_RESULT: u32 = 0;
    static mut NOTIFY_RESULT: u32 = 0;

    unsafe extern "C" fn record_release(element: *mut u8) -> u32 {
        RELEASE_CALLS += 1;
        RELEASE_ELEMENT = element as usize;
        RELEASE_RESULT
    }

    unsafe extern "C" fn record_addref(element: *mut u8) -> u32 {
        ADDREF_CALLS += 1;
        ADDREF_ELEMENT = element as usize;
        0xadd0_0000
    }

    unsafe extern "C" fn record_notify(
        list: *mut u8,
        tag: u32,
        context: *mut u8,
        flags: u32,
        stack_arg: u32,
    ) -> u32 {
        NOTIFY_CALLS += 1;
        NOTIFY_LIST = list as usize;
        NOTIFY_TAG = tag;
        NOTIFY_CONTEXT = context as usize;
        NOTIFY_FLAGS = flags;
        NOTIFY_STACK = stack_arg;
        NOTIFY_RESULT
    }

    struct OpsGuard(TdatFlag20Ops);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { TDAT_FLAG_20_OPS = self.0 };
        }
    }

    unsafe fn install_recorders(release_result: u32, notify_result: u32) -> OpsGuard {
        let previous = TDAT_FLAG_20_OPS;
        TDAT_FLAG_20_OPS = TdatFlag20Ops {
            refcount_release: record_release,
            refcount_addref: record_addref,
            tagged_list_notify: record_notify,
        };
        RELEASE_CALLS = 0;
        ADDREF_CALLS = 0;
        NOTIFY_CALLS = 0;
        RELEASE_ELEMENT = 0;
        ADDREF_ELEMENT = 0;
        NOTIFY_LIST = 0;
        NOTIFY_TAG = 0;
        NOTIFY_CONTEXT = 0;
        NOTIFY_FLAGS = u32::MAX;
        NOTIFY_STACK = u32::MAX;
        RELEASE_RESULT = release_result;
        NOTIFY_RESULT = notify_result;
        OpsGuard(previous)
    }

    /// A 0x60-byte element stand-in: word +0x0 (vtable, unread here), the
    /// class tag word at +0x4, and the flag byte at +0x20.
    fn element_with(tag: u32, flags: u8) -> [u32; 24] {
        let mut element = [0u32; 24];
        element[0] = 0x080d_adc8;
        element[1] = tag;
        element[FLAG_BYTE_OFFSET / 4] = u32::from(flags);
        element
    }

    unsafe fn flag_byte(element: &[u32; 24]) -> u8 {
        element.as_ptr().cast::<u8>().add(FLAG_BYTE_OFFSET).read()
    }

    #[test]
    fn unchanged_set_bit_returns_flags_without_side_effects() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let element = element_with(TDAT_CLASS_TAG, 0xe7);
        let _ops = unsafe { install_recorders(0x1111, 0x2222) };

        let result = unsafe { tdat_element_set_flag_20_bit_2(element.as_ptr() as *mut u8, 1) };

        assert_eq!(result, 0xe7);
        unsafe {
            assert_eq!(flag_byte(&element), 0xe7);
            assert_eq!((RELEASE_CALLS, ADDREF_CALLS, NOTIFY_CALLS), (0, 0, 0));
        }
    }

    #[test]
    fn unchanged_clear_bit_returns_flags_without_side_effects() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let element = element_with(TDAT_CLASS_TAG, 0xe3);
        let _ops = unsafe { install_recorders(0x1111, 0x2222) };

        let result = unsafe { tdat_element_set_flag_20_bit_2(element.as_ptr() as *mut u8, 0) };

        assert_eq!(result, 0xe3);
        unsafe {
            assert_eq!(flag_byte(&element), 0xe3);
            assert_eq!((RELEASE_CALLS, ADDREF_CALLS, NOTIFY_CALLS), (0, 0, 0));
        }
    }

    #[test]
    fn clearing_set_bit_preserves_other_bits_and_releases() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let element = element_with(TDAT_CLASS_TAG, 0xe7);
        let _ops = unsafe { install_recorders(0x5151, 0x2222) };

        let result = unsafe { tdat_element_set_flag_20_bit_2(element.as_ptr() as *mut u8, 0) };

        assert_eq!(result, 0x5151, "release result propagates");
        unsafe {
            assert_eq!(flag_byte(&element), 0xe3);
            assert_eq!((RELEASE_CALLS, ADDREF_CALLS, NOTIFY_CALLS), (1, 0, 0));
            assert_eq!(RELEASE_ELEMENT, element.as_ptr() as usize);
        }
    }

    #[test]
    fn setting_clear_bit_addrefs_and_notifies_with_exact_args() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let element = element_with(TDAT_CLASS_TAG, 0xe3);
        let _ops = unsafe { install_recorders(0x1111, 0x6262) };

        let result = unsafe { tdat_element_set_flag_20_bit_2(element.as_ptr() as *mut u8, 1) };

        assert_eq!(result, 0x6262, "notify result propagates");
        unsafe {
            assert_eq!(flag_byte(&element), 0xe7);
            assert_eq!((RELEASE_CALLS, ADDREF_CALLS, NOTIFY_CALLS), (0, 1, 1));
            let base = element.as_ptr() as usize;
            assert_eq!(ADDREF_ELEMENT, base);
            assert_eq!(NOTIFY_LIST, base + TAGGED_LIST_OFFSET);
            assert_eq!(NOTIFY_TAG, ENABLE_NOTIFY_TAG);
            assert_eq!(NOTIFY_CONTEXT, base);
            assert_eq!(NOTIFY_FLAGS, 0);
            assert_eq!(NOTIFY_STACK, 0);
        }
    }

    #[test]
    fn non_tdat_element_still_stores_byte_from_zero_base() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        // A 'plst'-tagged object: the class check fails, so the old flag
        // byte is treated as 0 — 0xff becomes 0x04, not 0xff.
        let element = element_with(OTHER_TAG, 0xff);
        let _ops = unsafe { install_recorders(0x1111, 0x2222) };

        let result = unsafe { tdat_element_set_flag_20_bit_2(element.as_ptr() as *mut u8, 1) };

        assert_eq!(result, 0x2222);
        unsafe {
            assert_eq!(flag_byte(&element), 0x04);
            assert_eq!((RELEASE_CALLS, ADDREF_CALLS, NOTIFY_CALLS), (0, 1, 1));
        }
    }

    #[test]
    fn non_tdat_element_zero_value_clears_and_releases() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let element = element_with(OTHER_TAG, 0xff);
        let _ops = unsafe { install_recorders(0x7171, 0x2222) };

        let result = unsafe { tdat_element_set_flag_20_bit_2(element.as_ptr() as *mut u8, 0) };

        assert_eq!(result, 0x7171);
        unsafe {
            assert_eq!(flag_byte(&element), 0x00);
            assert_eq!((RELEASE_CALLS, ADDREF_CALLS, NOTIFY_CALLS), (1, 0, 0));
        }
    }

    #[test]
    fn value_three_never_matches_early_return_but_sets_bit_zero() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        // Bit already set, value 3: the exact `cmp r2, #bit` against 1
        // fails, so the store and the enable path still run; only bit 0
        // of value reaches the byte.
        let element = element_with(TDAT_CLASS_TAG, 0xe7);
        let _ops = unsafe { install_recorders(0x1111, 0x2222) };

        let result = unsafe { tdat_element_set_flag_20_bit_2(element.as_ptr() as *mut u8, 3) };

        assert_eq!(result, 0x2222);
        unsafe {
            assert_eq!(flag_byte(&element), 0xe7);
            assert_eq!((RELEASE_CALLS, ADDREF_CALLS, NOTIFY_CALLS), (0, 1, 1));
        }
    }

    #[test]
    fn value_two_clears_bit_but_takes_enable_path() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        // Bit set, value 2: exact compare against 1 fails; (2 << 2) & 4
        // is 0 so the bit clears; value != 0 selects addref, not release.
        let element = element_with(TDAT_CLASS_TAG, 0xe7);
        let _ops = unsafe { install_recorders(0x1111, 0x2222) };

        let result = unsafe { tdat_element_set_flag_20_bit_2(element.as_ptr() as *mut u8, 2) };

        assert_eq!(result, 0x2222);
        unsafe {
            assert_eq!(flag_byte(&element), 0xe3);
            assert_eq!((RELEASE_CALLS, ADDREF_CALLS, NOTIFY_CALLS), (0, 1, 1));
        }
    }
}
