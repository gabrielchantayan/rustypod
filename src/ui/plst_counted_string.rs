//! 'plst' UI-element counted-string store and notification.
//!
//! - `plst_element_store_counted_string` — original: `FUN_08067274` @
//!   `0x08067274` (88 bytes including the literal event key at `0x080672cc`;
//!   10 direct `bl` call sites, all unconditional).

use core::ptr;

use crate::util::string_pool::{string_pool_store_counted, StringPool, PARAM_ERR};

use super::plst_class_check::ui_element_is_plst_class;

/// Word index of the inline `"crts"` string-pool object passed to
/// `string_pool_store_counted` (`add r0, r4, #0xcc`).
const STRING_POOL_WORD_INDEX: usize = 0xcc / core::mem::size_of::<u32>();

/// Word index of the string-pool entry id passed as the store out-pointer
/// (`add r2, r4, #0x124`).
const STRING_ID_WORD_INDEX: usize = 0x124 / core::mem::size_of::<u32>();

/// Word index of the tagged-handler list passed to `0x08066bb8`
/// (`add r0, r4, #0x48`).
const TAGGED_LIST_WORD_INDEX: usize = 0x48 / core::mem::size_of::<u32>();

/// Literal event key at 0x080672cc. Its semantic identity is not recovered.
const POST_STORE_NOTIFY_TAG: u32 = 0x6370_6e6d;

/// ABI of the still-unported tagged-handler list walker at `0x08066bb8`.
type TaggedListNotify = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tagged_list_notify(
    list: *mut u8,
    tag: u32,
    context: *mut u8,
    flags: u32,
    stack_arg: u32,
) {
    let notify: TaggedListNotify = core::mem::transmute(0x0806_6bb8usize);
    notify(list, tag, context, flags, stack_arg)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_tagged_list_notify(
    _list: *mut u8,
    _tag: u32,
    _context: *mut u8,
    _flags: u32,
    _stack_arg: u32,
) {}

/// Target dispatch boundary for the unported tagged-handler list walker.
///
/// `names.yaml` has no `ported` entry for `0x08066bb8`; this preserves its
/// stock target address without inventing a callee identity.
pub static mut PLST_COUNTED_STRING_OPS: TaggedListNotify = retail_tagged_list_notify;

#[inline(always)]
unsafe fn tagged_list_notify() -> TaggedListNotify {
    ptr::read_volatile(ptr::addr_of!(PLST_COUNTED_STRING_OPS))
}

/// plst_element_store_counted_string — original: `FUN_08067274` @
/// `0x08067274` (88 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec`:
///
/// ```text
/// 08067274  push {r3,r4,r5,lr}
/// 08067278  mov  r4,r0
/// 0806727c  mov  r3,r1
/// 08067280  bl   0x080613e0       ; ui_element_is_plst_class
/// 08067284  cmp  r0,#0
/// 08067288  cmpne r3,#0
/// 0806728c  mvneq r0,#0x31        ; -50 (paramErr)
/// 08067290  beq  0x080672c8
/// 08067294  add  r2,r4,#0x124
/// 08067298  mov  r1,r3
/// 0806729c  add  r0,r4,#0xcc
/// 080672a0  bl   0x080be81c       ; string_pool_store_counted
/// 080672a4  movs r5,r0
/// 080672a8  bne  0x080672c4
/// 080672ac  mov  r3,#0
/// 080672b0  ldr  r1,[pc,#0x14]    ; 0x63706e6d @ 0x080672cc
/// 080672b4  mov  r2,r4
/// 080672b8  add  r0,r4,#0x48
/// 080672bc  str  r3,[sp]
/// 080672c0  bl   0x08066bb8
/// 080672c4  mov  r0,r5
/// 080672c8  pop  {r3,r4,r5,pc}
/// 080672cc  .word 0x63706e6d
/// ```
///
/// The next separately linked function starts at `0x080672d0`, so the
/// literal pool proves the 88-byte extent Ghidra reports. Decoding every ARM
/// B/BL word in `osos.dec` finds exactly 10 direct callers, all unconditional
/// `bl` (0x080612e0, 0x08063500, 0x08065c5c, 0x08068a38, 0x080ab4a8,
/// 0x080b4a30, 0x0812cb8c, 0x0816ed6c, 0x0816ee34, 0x0817c0f4), and no
/// predicated forms. The internal class and NULL checks therefore protect
/// every caller.
///
/// Algorithm: require a non-NULL `'plst'` element and a non-NULL counted
/// UTF-16 source. Store that source into the element's inline string pool at
/// +0xcc, replacing the entry id at +0x124. On a zero store status, notify the
/// tagged-handler list at +0x48 with the unrecovered literal key
/// `0x63706e6d`, the element as context, and two zero arguments. Return the
/// store status; notification status is discarded.
///
/// Deliberate deviations: the already-ported
/// [`string_pool_store_counted`] is called directly. The unported
/// `0x08066bb8` tagged-list walker dispatches through the volatile
/// [`PLST_COUNTED_STRING_OPS`] boundary, whose target default calls its retail
/// address. The literal notification key remains a raw value because its
/// semantic identity is not established.
///
/// # Safety
///
/// `element` may be NULL; a non-NULL element must contain its class tag at
/// +0x4. A qualifying element must provide writable inline pool storage
/// through +0x127, and `counted` must point to a readable length-prefixed
/// UTF-16 string.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.plst_element_store_counted_string")]
pub unsafe extern "C" fn plst_element_store_counted_string(
    element: *mut u8,
    counted: *const u16,
) -> i32 {
    if ui_element_is_plst_class(element) == 0 || counted.is_null() {
        return PARAM_ERR;
    }

    let words = element.cast::<u32>();
    let status = string_pool_store_counted(
        words.add(STRING_POOL_WORD_INDEX).cast::<StringPool>(),
        counted,
        words.add(STRING_ID_WORD_INDEX).cast::<i32>(),
    );
    if status == 0 {
        tagged_list_notify()(
            words.add(TAGGED_LIST_WORD_INDEX).cast::<u8>(),
            POST_STORE_NOTIFY_TAG,
            element,
            0,
            0,
        );
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::mem::size_of;
    use super::*;
    use crate::util::string_pool::{StringPoolStore, STRING_POOL_STORE};
    use std::sync::Mutex;

    const PLST_CLASS_TAG: u32 = 0x706c_7374;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut STORE_CALLS: u32 = 0;
    static mut STORE_POOL: usize = 0;
    static mut STORE_DATA: usize = 0;
    static mut STORE_LEN: u32 = 0;
    static mut STORE_ID_OUT: usize = 0;
    static mut STORE_STATUS: i32 = 0;
    static mut NOTIFY_CALLS: u32 = 0;
    static mut NOTIFY_LIST: usize = 0;
    static mut NOTIFY_TAG: u32 = 0;
    static mut NOTIFY_CONTEXT: usize = 0;
    static mut NOTIFY_FLAGS: u32 = u32::MAX;
    static mut NOTIFY_STACK_ARG: u32 = u32::MAX;

    unsafe extern "C" fn record_store(
        pool: *mut StringPool,
        data: *const u8,
        len: u32,
        id_out: *mut i32,
    ) -> i32 {
        STORE_CALLS += 1;
        STORE_POOL = pool as usize;
        STORE_DATA = data as usize;
        STORE_LEN = len;
        STORE_ID_OUT = id_out as usize;
        STORE_STATUS
    }

    unsafe extern "C" fn record_notify(
        list: *mut u8,
        tag: u32,
        context: *mut u8,
        flags: u32,
        stack_arg: u32,
    ) {
        NOTIFY_CALLS += 1;
        NOTIFY_LIST = list as usize;
        NOTIFY_TAG = tag;
        NOTIFY_CONTEXT = context as usize;
        NOTIFY_FLAGS = flags;
        NOTIFY_STACK_ARG = stack_arg;
    }

    struct Guard {
        store: StringPoolStore,
        notify: TaggedListNotify,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                STRING_POOL_STORE = self.store;
                PLST_COUNTED_STRING_OPS = self.notify;
            }
        }
    }

    unsafe fn install_recorders(status: i32) -> Guard {
        let previous = Guard {
            store: STRING_POOL_STORE,
            notify: PLST_COUNTED_STRING_OPS,
        };
        STRING_POOL_STORE = record_store;
        PLST_COUNTED_STRING_OPS = record_notify;
        STORE_CALLS = 0;
        STORE_POOL = 0;
        STORE_DATA = 0;
        STORE_LEN = 0;
        STORE_ID_OUT = 0;
        STORE_STATUS = status;
        NOTIFY_CALLS = 0;
        NOTIFY_LIST = 0;
        NOTIFY_TAG = 0;
        NOTIFY_CONTEXT = 0;
        NOTIFY_FLAGS = u32::MAX;
        NOTIFY_STACK_ARG = u32::MAX;
        previous
    }

    /// 0x128 bytes cover the class tag (+0x4), list (+0x48), inline pool
    /// (+0xcc), and entry id (+0x124) on aligned word boundaries.
    fn element_with_tag(tag: u32) -> [u32; 74] {
        let mut element = [0u32; 74];
        element[1] = tag;
        element
    }

    #[test]
    fn valid_element_stores_counted_utf16_and_notifies_exactly() {
        let _ops = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _store = crate::util::string_pool::STRING_POOL_SEAM_LOCK
            .lock().unwrap_or_else(|error| error.into_inner());
        let _guard = unsafe { install_recorders(0) };
        let mut element = element_with_tag(PLST_CLASS_TAG);
        let counted = [3u16, 0x0041, 0x03a9, 0x0000];

        let status = unsafe {
            plst_element_store_counted_string(element.as_mut_ptr().cast(), counted.as_ptr())
        };

        unsafe {
            let base = element.as_ptr() as usize;
            assert_eq!(status, 0);
            assert_eq!(STORE_CALLS, 1);
            assert_eq!(STORE_POOL, base + STRING_POOL_WORD_INDEX * size_of::<u32>());
            assert_eq!(STORE_DATA, counted.as_ptr().add(1) as usize);
            assert_eq!(STORE_LEN, 6);
            assert_eq!(STORE_ID_OUT, base + STRING_ID_WORD_INDEX * size_of::<u32>());
            assert_eq!(NOTIFY_CALLS, 1);
            assert_eq!(NOTIFY_LIST, base + TAGGED_LIST_WORD_INDEX * size_of::<u32>());
            assert_eq!(NOTIFY_TAG, POST_STORE_NOTIFY_TAG);
            assert_eq!(NOTIFY_CONTEXT, base);
            assert_eq!(NOTIFY_FLAGS, 0);
            assert_eq!(NOTIFY_STACK_ARG, 0);
        }
    }

    #[test]
    fn store_failure_propagates_without_notification() {
        let _ops = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _store = crate::util::string_pool::STRING_POOL_SEAM_LOCK
            .lock().unwrap_or_else(|error| error.into_inner());
        let _guard = unsafe { install_recorders(-108) };
        let mut element = element_with_tag(PLST_CLASS_TAG);
        let counted = [0u16];

        let status = unsafe {
            plst_element_store_counted_string(element.as_mut_ptr().cast(), counted.as_ptr())
        };

        unsafe {
            assert_eq!(status, -108);
            assert_eq!(STORE_CALLS, 1);
            assert_eq!(NOTIFY_CALLS, 0);
        }
    }

    #[test]
    fn null_counted_source_returns_param_error_without_calls() {
        let _ops = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _store = crate::util::string_pool::STRING_POOL_SEAM_LOCK
            .lock().unwrap_or_else(|error| error.into_inner());
        let _guard = unsafe { install_recorders(0) };
        let mut element = element_with_tag(PLST_CLASS_TAG);

        let status = unsafe {
            plst_element_store_counted_string(element.as_mut_ptr().cast(), core::ptr::null())
        };

        unsafe {
            assert_eq!(status, PARAM_ERR);
            assert_eq!(STORE_CALLS, 0);
            assert_eq!(NOTIFY_CALLS, 0);
        }
    }

    #[test]
    fn null_and_foreign_elements_return_param_error_without_calls() {
        let _ops = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _store = crate::util::string_pool::STRING_POOL_SEAM_LOCK
            .lock().unwrap_or_else(|error| error.into_inner());
        let _guard = unsafe { install_recorders(0) };
        let counted = [1u16, 0x0041];
        let mut foreign = element_with_tag(0x7464_6174);

        let null_status = unsafe {
            plst_element_store_counted_string(core::ptr::null_mut(), counted.as_ptr())
        };
        let foreign_status = unsafe {
            plst_element_store_counted_string(foreign.as_mut_ptr().cast(), counted.as_ptr())
        };

        unsafe {
            assert_eq!((null_status, foreign_status), (PARAM_ERR, PARAM_ERR));
            assert_eq!(STORE_CALLS, 0);
            assert_eq!(NOTIFY_CALLS, 0);
        }
    }
}
