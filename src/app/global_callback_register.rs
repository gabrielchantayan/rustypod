//! Global callback registration — original: `FUN_08292788` @ `0x08292788`
//! (128 bytes of code, `0x08292788..0x08292804`; the two following words are
//! its literal pool and the next separately linked function starts at
//! `0x08292810`).
//!
//! Raw ARM locks the global callback-list mutex, walks the circular list at
//! `0x08ad2c68`, and appends the supplied opaque callback word only if no node
//! already has that word at `+0x08`. The append member at `0x083dd660` is still
//! retail code, so target builds call its fixed address through a typed function
//! pointer while host tests install an equivalent operation.
//!
//! **Eight direct inbound `bl` callers, verified by decoding every ARM B/BL
//! immediate in `osos.dec`:** `0x0816e3fc`, `0x0819e888`, `0x081a0fd4`,
//! `0x081b8304`, `0x081b8bb0`, `0x081db82c`, `0x081ea538`, and `0x081ea5dc`.
//! All are unconditional; there are no predicated calls. Thus this helper has
//! no caller-side predicate and its body supplies no NULL guard.
//!
//! Deliberate deviation: the unported `std::list` append @ `0x083dd660` crosses
//! [`GLOBAL_CALLBACK_REGISTER_OPS`] on host only. Target builds retain a typed
//! call through the fixed retail address. The mutex and dereference comparator
//! called directly.

use core::ptr::addr_of;
#[cfg(not(target_os = "none"))]
use core::ptr::{addr_of_mut, read_volatile};

use crate::cxx::templates::not_equal_deref;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

const CALLBACK_MUTEX_ADDRESS: usize = 0x08ad_2c4c;
const CALLBACK_LIST_ADDRESS: usize = 0x08ad_2c68;

/// The opaque global callback-list header.
///
/// `sentinel` at `+0x10` points to the circular list sentinel; the retail
/// append member owns every other header word.
#[repr(C)]
struct CallbackList {
    _unknown_00: u32,
    _free_node: u32,
    _unknown_08: u32,
    _unknown_0c: u32,
    sentinel: u32,
    _count: u32,
}

const _: () = assert!(core::mem::size_of::<CallbackList>() == 0x18);
const _: [u8; 0x10] = [0; core::mem::offset_of!(CallbackList, sentinel)];

/// The node words this helper inspects before deferring to list append.
#[repr(C)]
struct CallbackNode {
    next: u32,
    _previous: u32,
    callback: u32,
}

const _: () = assert!(core::mem::size_of::<CallbackNode>() == 0x0c);
const _: [u8; 0x08] = [0; core::mem::offset_of!(CallbackNode, callback)];

/// ABI of the one-word `std::list` append helper at `0x083dd660`.
type CallbackListAppend = unsafe extern "C" fn(list: *mut CallbackList, callback: *const u32);

/// The still-retail list operation reached by this function.
#[derive(Clone, Copy)]
pub struct GlobalCallbackRegisterOps {
    pub append: CallbackListAppend,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_callback_list_append(list: *mut CallbackList, callback: *const u32) {
    let append: CallbackListAppend = core::mem::transmute(0x083d_d660usize);
    append(list, callback);
}

#[cfg(target_os = "none")]
const DEFAULT_GLOBAL_CALLBACK_REGISTER_OPS: GlobalCallbackRegisterOps = GlobalCallbackRegisterOps {
    append: retail_callback_list_append,
};

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_callback_list_append(
    _list: *mut CallbackList,
    _callback: *const u32,
) {
    panic!("install global callback register host operations before calling")
}

/// Host default before tests install a retail-equivalent list append.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_GLOBAL_CALLBACK_REGISTER_OPS: GlobalCallbackRegisterOps =
    GlobalCallbackRegisterOps { append: missing_callback_list_append };

/// Host seam for the unported retail list append.
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_CALLBACK_REGISTER_OPS: GlobalCallbackRegisterOps =
    DEFAULT_GLOBAL_CALLBACK_REGISTER_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn register_ops() -> GlobalCallbackRegisterOps {
    DEFAULT_GLOBAL_CALLBACK_REGISTER_OPS
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn register_ops() -> GlobalCallbackRegisterOps {
    read_volatile(addr_of!(GLOBAL_CALLBACK_REGISTER_OPS))
}

#[cfg(not(target_os = "none"))]
static mut HOST_CALLBACK_LIST: *mut CallbackList = core::ptr::null_mut();
#[cfg(not(target_os = "none"))]
static mut HOST_CALLBACK_MUTEX: PosixMutex = PosixMutex {
    magic: 0,
    owner: 0,
    reserved_08: 0,
    attr_flags: 0,
    reserved_10: 0,
    recursion: 0,
    sem_handle: 0,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn callback_globals() -> (*mut CallbackList, *mut PosixMutex) {
    (CALLBACK_LIST_ADDRESS as *mut CallbackList, CALLBACK_MUTEX_ADDRESS as *mut PosixMutex)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn callback_globals() -> (*mut CallbackList, *mut PosixMutex) {
    (read_volatile(addr_of!(HOST_CALLBACK_LIST)), addr_of_mut!(HOST_CALLBACK_MUTEX))
}

/// Registers `callback` in the global callback list unless it is already
/// present.
///
/// Original: `FUN_08292788` at `0x08292788` (128 bytes; **8 direct plain
/// `bl` callers, no predicated forms**). The callback is an opaque firmware
/// word, including zero. The original validates neither the callback nor the
/// list state.
///
/// # Safety
///
/// On target, the fixed callback-list state must retain its retail layout. On
/// host, callers must install a valid list fixture and
/// [`GLOBAL_CALLBACK_REGISTER_OPS`]. Node links are 32-bit target pointers and
/// must be valid until this call returns.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_callback_register(callback: u32) {
    let (callback_list, mutex) = callback_globals();
    let _ = posix_mutex_lock(mutex);

    let sentinel = (*callback_list).sentinel;
    let mut cursor = (*(sentinel as usize as *const CallbackNode)).next;
    loop {
        let end = (*callback_list).sentinel;
        if not_equal_deref(addr_of!(cursor), addr_of!(end)) == 0 {
            (register_ops().append)(callback_list, addr_of!(callback));
            break;
        }

        let node = cursor as usize as *mut CallbackNode;
        if (*node).callback == callback {
            break;
        }
        cursor = (*node).next;
    }

    let _ = posix_mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::{Mutex, MutexGuard};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const SENTINEL_OFFSET: usize = 0x100;
    const FIRST_NODE_OFFSET: usize = 0x140;
    const SECOND_NODE_OFFSET: usize = 0x180;
    const THIRD_NODE_OFFSET: usize = 0x1c0;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::GLOBAL_CALLBACK_REGISTER, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    static mut APPEND_CALLS: u32 = 0;
    static mut APPENDED_CALLBACK: u32 = 0;
    static mut APPENDED_LIST: usize = 0;

    fn try_fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock();
        (*FIXTURE).map(|base| (base as *mut u8, guard))
    }

    unsafe fn list(base: *mut u8) -> *mut CallbackList {
        base.cast::<CallbackList>()
    }

    unsafe fn node(base: *mut u8, offset: usize) -> *mut CallbackNode {
        base.add(offset).cast::<CallbackNode>()
    }

    unsafe fn build_list(base: *mut u8, callbacks: [u32; 3]) {
        base.write_bytes(0, FIXTURE_LEN);
        let sentinel = node(base, SENTINEL_OFFSET);
        let first = node(base, FIRST_NODE_OFFSET);
        let second = node(base, SECOND_NODE_OFFSET);
        let third = node(base, THIRD_NODE_OFFSET);
        sentinel.write(CallbackNode { next: first as u32, _previous: third as u32, callback: 0 });
        first.write(CallbackNode { next: second as u32, _previous: sentinel as u32, callback: callbacks[0] });
        second.write(CallbackNode { next: third as u32, _previous: first as u32, callback: callbacks[1] });
        third.write(CallbackNode { next: sentinel as u32, _previous: second as u32, callback: callbacks[2] });
        list(base).write(CallbackList {
            _unknown_00: 0,
            _free_node: 0,
            _unknown_08: 0,
            _unknown_0c: 0,
            sentinel: sentinel as u32,
            _count: 3,
        });
        HOST_CALLBACK_LIST = list(base);
        HOST_CALLBACK_MUTEX = PosixMutex {
            magic: 0,
            owner: 0,
            reserved_08: 0,
            attr_flags: 0,
            reserved_10: 0,
            recursion: 0,
            sem_handle: 0,
        };
        APPEND_CALLS = 0;
        APPENDED_CALLBACK = 0;
        APPENDED_LIST = 0;
        GLOBAL_CALLBACK_REGISTER_OPS = GlobalCallbackRegisterOps { append: record_append };
    }

    unsafe extern "C" fn record_append(callback_list: *mut CallbackList, callback: *const u32) {
        APPEND_CALLS += 1;
        APPENDED_CALLBACK = callback.read();
        APPENDED_LIST = callback_list as usize;
    }

    #[test]
    fn appends_absent_zero_callback_after_full_scan() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("global_callback_register");
            return;
        };
        unsafe {
            build_list(base, [1, 2, u32::MAX]);
            global_callback_register(0);
            assert_eq!(APPEND_CALLS, 1);
            assert_eq!(APPENDED_CALLBACK, 0, "zero is a valid opaque callback word");
            assert_eq!(APPENDED_LIST, list(base) as usize);
            assert_eq!((*list(base))._count, 3, "the append member owns list mutation");
            assert_eq!((*node(base, THIRD_NODE_OFFSET)).next, node(base, SENTINEL_OFFSET) as u32);
            assert_eq!(HOST_CALLBACK_MUTEX.owner, 0, "the ignored lock status cannot skip unlock");
            assert_eq!(HOST_CALLBACK_MUTEX.recursion, 0);
        }
    }

    #[test]
    fn duplicate_callback_skips_append_and_unlocks() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("global_callback_register");
            return;
        };
        unsafe {
            build_list(base, [0x11, 0x22, 0x22]);
            global_callback_register(0x22);
            assert_eq!(APPEND_CALLS, 0, "the first duplicate terminates the walk");
            assert_eq!((*list(base))._count, 3);
            assert_eq!((*node(base, FIRST_NODE_OFFSET)).next, node(base, SECOND_NODE_OFFSET) as u32);
            assert_eq!((*node(base, THIRD_NODE_OFFSET)).callback, 0x22);
            assert_eq!(HOST_CALLBACK_MUTEX.owner, 0);
            assert_eq!(HOST_CALLBACK_MUTEX.recursion, 0);
        }
    }
}
