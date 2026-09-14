//! UI-element change notification.
//!
//! - `notify_element_change` — original: `FUN_0805d398` @ `0x0805d398`
//!   (92 bytes including the literal event key at `0x0805d3f4`; 6 direct
//!   `bl` call sites: 4 unconditional and 2 `blne`).

use core::ptr;

use super::tdat_flag_20_bit_2::tdat_element_set_flag_20_bit_2;

/// Bits in the first notification payload word that do not require setting
/// the element's pending-notification flag (`bic r0, r0, #0x60000000` /
/// `bic r0, r0, #0x20000`).
const IGNORED_CHANGE_DATA_BITS: u32 = 0x6002_0000;

/// Bits in the second notification payload word that do not require setting
/// the element's pending-notification flag (`bic r1, r1, #0xc00000`).
const IGNORED_CHANGE_FLAGS: u32 = 0x00c0_0000;

/// Byte offset of the element's tagged-handler list (`add r0, r0, #0x54`).
const TAGGED_LIST_OFFSET: usize = 0x54;

/// Literal event key at `0x0805d3f4`. Its semantic identity is not recovered.
const ELEMENT_CHANGE_NOTIFY_TAG: u32 = 0x6d74_7269;

/// ABI of the still-unported tagged-handler list walker at `0x08066bb8` for
/// this notification: `(list, tag, owner, payload_pair, stack_arg)`.
pub type ElementChangeNotify =
    unsafe extern "C" fn(*mut u8, u32, *mut u32, *const u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_element_change_notify(
    list: *mut u8,
    tag: u32,
    owner: *mut u32,
    payload_pair: *const u32,
    stack_arg: u32,
) {
    let notify: ElementChangeNotify = core::mem::transmute(0x0806_6bb8usize);
    notify(list, tag, owner, payload_pair, stack_arg)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_element_change_notify(
    _list: *mut u8,
    _tag: u32,
    _owner: *mut u32,
    _payload_pair: *const u32,
    _stack_arg: u32,
) {}

/// Target dispatch boundary for the unported tagged-handler list walker.
///
/// `names.yaml` has no `ported` entry for `0x08066bb8`; this preserves its
/// retail address without inventing a callee identity.
pub static mut ELEMENT_CHANGE_NOTIFY_OPS: ElementChangeNotify = retail_element_change_notify;

#[inline(always)]
unsafe fn element_change_notify() -> ElementChangeNotify {
    ptr::read_volatile(ptr::addr_of!(ELEMENT_CHANGE_NOTIFY_OPS))
}

/// notify_element_change — original: `FUN_0805d398` @ `0x0805d398` (92
/// bytes including its literal event key).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x0805d398..0x0805d3f8`:
///
/// ```text
/// 0805d398  push  {r0,r1,r2,r3,r4,r5,ip,lr}
/// 0805d39c  sub   sp,sp,#8
/// 0805d3a0  mov   r4,r0
/// 0805d3a4  ldrd  r0,[sp,#16]        ; change_data, change_flags
/// 0805d3a8  bic   r0,r0,#0x60000000
/// 0805d3ac  bic   r1,r1,#0x00c00000
/// 0805d3b0  cmp   r1,#0
/// 0805d3b4  bic   r0,r0,#0x20000
/// 0805d3b8  mov   r2,#0
/// 0805d3bc  cmpeq r0,r2
/// 0805d3c0  ldrne r0,[r4]
/// 0805d3c4  movne r1,#1
/// 0805d3c8  blne  0x08067b4c
/// 0805d3cc  mov   r3,#0
/// 0805d3d0  str   r3,[sp]
/// 0805d3d4  ldr   r0,[r4]
/// 0805d3d8  ldr   r1,[pc,#20]        ; 0x6d747269 @ 0x0805d3f4
/// 0805d3dc  add   r3,sp,#16
/// 0805d3e0  mov   r2,r4
/// 0805d3e4  add   r0,r0,#0x54
/// 0805d3e8  bl    0x08066bb8
/// 0805d3ec  add   sp,sp,#24
/// 0805d3f0  pop   {r4,r5,ip,pc}
/// 0805d3f4  .word 0x6d747269
/// ```
///
/// The next independently linked function begins at `0x0805d3f8`, confirming
/// the 92-byte extent. Decoding every ARM B/BL word in `osos.dec` finds six
/// direct call sites: four unconditional `bl` (0x08067c64, 0x0826ff5c,
/// 0x0826ffd8, 0x0827030c) and two `blne` (0x0806cdfc, 0x080a7ba0). The
/// predicated callers gate this notification on their own state.
///
/// Algorithm: when either payload word retains a bit outside its ignored mask,
/// set bit 2 of the target 'tdat' element's flag byte through the existing
/// `tdat_element_set_flag_20_bit_2` port. Always walk that element's
/// tagged-handler list at +0x54 with the unrecovered literal event key, the
/// owner as context, a stack-local two-word payload `(change_data,
/// change_flags)`, and a zero fifth argument. Both callee results are
/// discarded.
///
/// Deliberate deviations: the already-ported flag setter is called directly.
/// The unported list walker at `0x08066bb8` dispatches through the volatile
/// [`ELEMENT_CHANGE_NOTIFY_OPS`] seam, whose target default calls its retail
/// address. The literal key's identity is not claimed.
///
/// # Safety
///
/// `owner` must be non-NULL and point to a readable 32-bit target pointer to
/// an element. That element must be writable through +0x20 when the payload
/// requires its pending flag, and readable through +0x57 for the retail list
/// walker.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.notify_element_change")]
#[inline(never)]
pub unsafe extern "C" fn notify_element_change(
    owner: *mut u32,
    _previous_value: u32,
    change_data: u32,
    change_flags: u32,
) {
    let element = owner.read() as usize as *mut u8;
    if change_data & !IGNORED_CHANGE_DATA_BITS != 0
        || change_flags & !IGNORED_CHANGE_FLAGS != 0
    {
        tdat_element_set_flag_20_bit_2(element, 1);
    }

    let payload_pair = [change_data, change_flags];
    element_change_notify()(
        element.add(TAGGED_LIST_OFFSET),
        ELEMENT_CHANGE_NOTIFY_TAG,
        owner,
        payload_pair.as_ptr(),
        0,
    );
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const TDAT_CLASS_TAG: u32 = 0x7464_6174;
    const ELEMENT_BYTES: usize = 0x60;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static ELEMENT_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::UI_ELEMENT_CHANGE_NOTIFY, ELEMENT_BYTES)
            .map(|element| element as usize)
    });
    static mut NOTIFY_CALLS: u32 = 0;
    static mut NOTIFY_LIST: usize = 0;
    static mut NOTIFY_TAG: u32 = 0;
    static mut NOTIFY_OWNER: usize = 0;
    static mut NOTIFY_CHANGE_DATA: u32 = 0;
    static mut NOTIFY_CHANGE_FLAGS: u32 = 0;
    static mut NOTIFY_STACK_ARG: u32 = u32::MAX;

    unsafe extern "C" fn record_notify(
        list: *mut u8,
        tag: u32,
        owner: *mut u32,
        payload_pair: *const u32,
        stack_arg: u32,
    ) {
        NOTIFY_CALLS += 1;
        NOTIFY_LIST = list as usize;
        NOTIFY_TAG = tag;
        NOTIFY_OWNER = owner as usize;
        NOTIFY_CHANGE_DATA = payload_pair.read();
        NOTIFY_CHANGE_FLAGS = payload_pair.add(1).read();
        NOTIFY_STACK_ARG = stack_arg;
    }

    struct OpsGuard(ElementChangeNotify);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { ELEMENT_CHANGE_NOTIFY_OPS = self.0 };
        }
    }

    unsafe fn install_recorder() -> OpsGuard {
        let previous = ELEMENT_CHANGE_NOTIFY_OPS;
        ELEMENT_CHANGE_NOTIFY_OPS = record_notify;
        NOTIFY_CALLS = 0;
        NOTIFY_LIST = 0;
        NOTIFY_TAG = 0;
        NOTIFY_OWNER = 0;
        NOTIFY_CHANGE_DATA = 0;
        NOTIFY_CHANGE_FLAGS = 0;
        NOTIFY_STACK_ARG = u32::MAX;
        OpsGuard(previous)
    }

    unsafe fn fixture() -> Option<(*mut u8, [u32; 1])> {
        let element = (*ELEMENT_FIXTURE)? as *mut u8;
        core::ptr::write_bytes(element, 0, ELEMENT_BYTES);
        element.cast::<u32>().add(1).write(TDAT_CLASS_TAG);
        Some((element, [element as usize as u32]))
    }

    #[test]
    fn ignored_payload_still_notifies_without_setting_pending_flag() {
        let _tdat_lock = crate::testing::TDAT_FLAG_20_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _ops_lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((element, mut owner)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let _ops = unsafe { install_recorder() };

        unsafe {
            notify_element_change(
                owner.as_mut_ptr(),
                0x55,
                IGNORED_CHANGE_DATA_BITS,
                IGNORED_CHANGE_FLAGS,
            );
        }

        unsafe {
            assert_eq!(element.add(0x20).read(), 0);
            assert_eq!(NOTIFY_CALLS, 1);
            assert_eq!(NOTIFY_LIST, element.add(TAGGED_LIST_OFFSET) as usize);
            assert_eq!(NOTIFY_TAG, ELEMENT_CHANGE_NOTIFY_TAG);
            assert_eq!(NOTIFY_OWNER, owner.as_mut_ptr() as usize);
            assert_eq!(NOTIFY_CHANGE_DATA, IGNORED_CHANGE_DATA_BITS);
            assert_eq!(NOTIFY_CHANGE_FLAGS, IGNORED_CHANGE_FLAGS);
            assert_eq!(NOTIFY_STACK_ARG, 0);
        }
    }

    #[test]
    fn meaningful_payload_sets_pending_flag_and_forwards_pair() {
        let _tdat_lock = crate::testing::TDAT_FLAG_20_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _ops_lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((element, mut owner)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let _ops = unsafe { install_recorder() };
        const CHANGE_DATA: u32 = 0x6000_0001;
        const CHANGE_FLAGS: u32 = 0x00c0_0040;

        unsafe {
            notify_element_change(owner.as_mut_ptr(), 0x1234_5678, CHANGE_DATA, CHANGE_FLAGS);
        }

        unsafe {
            assert_eq!(element.add(0x20).read(), 4);
            assert_eq!(NOTIFY_CALLS, 1);
            assert_eq!(NOTIFY_CHANGE_DATA, CHANGE_DATA);
            assert_eq!(NOTIFY_CHANGE_FLAGS, CHANGE_FLAGS);
        }
    }
}
