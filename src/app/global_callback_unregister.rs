//! Global callback unregistration — original: `FUN_082928d8` @ `0x082928d8`
//! (172 bytes of code, `0x082928d8..0x08292880`; the following four words are
//! its literal pool and the next separately linked function starts at
//! `0x08292994`).
//!
//! Raw ARM locks the global callback-list mutex, then selects one of two
//! paths from the dispatch-active byte. Outside dispatch it walks the circular
//! list at `0x08ad2c68`, comparing each node's callback word at `+0x08`, and
//! erases the first match. During dispatch it leaves that list untouched and
//! appends the callback word to the deferred-removal list at `0x08ad2c80`.
//! It always unlocks and ignores both mutex statuses.
//!
//! **Ten direct `bl` callers, verified by decoding every ARM B/BL immediate
//! in `osos.dec`: six unconditional, two `bleq` (at `0x08198f04` and
//! `0x081b8d44`), and two `blne` (at `0x081a13d4` and `0x081eaa7c`).** The
//! predicated callers gate unregistration themselves; this body has no NULL
//! guard for either a callback word or its list state.
//!
//! Deliberate deviation: `std::list` erase @ `0x083dd5f4` and append @
//! `0x083dd660` are not ported (and have no `names.yaml` port entries), so
//! target builds call their fixed retail addresses while host tests install
//! equivalent operations through [`GLOBAL_CALLBACK_UNREGISTER_OPS`]. The
//! mutex and dereference comparator are already ported and are called
//! directly.

use core::ptr::{addr_of, addr_of_mut, read_volatile};

use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};
use crate::cxx::templates::not_equal_deref;

const CALLBACK_DISPATCH_ACTIVE_ADDRESS: usize = 0x089c_fd54;
const CALLBACK_MUTEX_ADDRESS: usize = 0x08ad_2c4c;
const CALLBACK_LIST_ADDRESS: usize = 0x08ad_2c68;
const DEFERRED_REMOVAL_LIST_ADDRESS: usize = 0x08ad_2c80;

/// The opaque list header fields this wrapper reaches.
///
/// `sentinel` at `+0x10` points to the circular list sentinel; the erased and
/// appended retail routines own every other header word.
#[repr(C)]
pub struct CallbackList {
    _unknown_00: u32,
    _free_node: u32,
    _unknown_08: u32,
    _unknown_0c: u32,
    sentinel: u32,
    _count: u32,
}

const _: () = assert!(core::mem::size_of::<CallbackList>() == 0x18);
const _: [u8; 0x10] = [0; core::mem::offset_of!(CallbackList, sentinel)];

/// The list node fields this wrapper reads before delegating the erase.
#[repr(C)]
struct CallbackNode {
    next: u32,
    _previous: u32,
    callback: u32,
}

const _: () = assert!(core::mem::size_of::<CallbackNode>() == 0x0c);
const _: [u8; 0x08] = [0; core::mem::offset_of!(CallbackNode, callback)];

/// ABI of `std::list::erase` at `0x083dd5f4`.
pub type CallbackListErase = unsafe extern "C" fn(
    next: *mut u32,
    list: *mut CallbackList,
    cursor: *const u32,
);

/// ABI of the one-word `std::list` append helper at `0x083dd660`.
pub type DeferredCallbackAppend = unsafe extern "C" fn(
    list: *mut CallbackList,
    callback: *const u32,
);

/// The two still-retail list operations reached by this wrapper.
#[derive(Clone, Copy)]
pub struct GlobalCallbackUnregisterOps {
    pub erase: CallbackListErase,
    pub append_deferred: DeferredCallbackAppend,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_callback_list_erase(
    next: *mut u32,
    list: *mut CallbackList,
    cursor: *const u32,
) {
    let erase: CallbackListErase = core::mem::transmute(0x083d_d5f4usize);
    erase(next, list, cursor);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_deferred_callback_append(
    list: *mut CallbackList,
    callback: *const u32,
) {
    let append: DeferredCallbackAppend = core::mem::transmute(0x083d_d660usize);
    append(list, callback);
}

#[cfg(target_os = "none")]
const DEFAULT_GLOBAL_CALLBACK_UNREGISTER_OPS: GlobalCallbackUnregisterOps =
    GlobalCallbackUnregisterOps {
        erase: retail_callback_list_erase,
        append_deferred: retail_deferred_callback_append,
    };

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_callback_list_erase(
    _next: *mut u32,
    _list: *mut CallbackList,
    _cursor: *const u32,
) {
    panic!("install global callback unregister host operations before calling")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_deferred_callback_append(
    _list: *mut CallbackList,
    _callback: *const u32,
) {
    panic!("install global callback unregister host operations before calling")
}

/// Host default before tests install retail-equivalent list operations.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_GLOBAL_CALLBACK_UNREGISTER_OPS: GlobalCallbackUnregisterOps =
    GlobalCallbackUnregisterOps {
        erase: missing_callback_list_erase,
        append_deferred: missing_deferred_callback_append,
    };

/// Host seam for the two unported retail list operations.
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_CALLBACK_UNREGISTER_OPS: GlobalCallbackUnregisterOps =
    DEFAULT_GLOBAL_CALLBACK_UNREGISTER_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unregister_ops() -> GlobalCallbackUnregisterOps {
    DEFAULT_GLOBAL_CALLBACK_UNREGISTER_OPS
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn unregister_ops() -> GlobalCallbackUnregisterOps {
    read_volatile(addr_of!(GLOBAL_CALLBACK_UNREGISTER_OPS))
}

#[cfg(not(target_os = "none"))]
static mut HOST_CALLBACK_DISPATCH_ACTIVE: u8 = 0;
#[cfg(not(target_os = "none"))]
static mut HOST_CALLBACK_LIST: *mut CallbackList = core::ptr::null_mut();
#[cfg(not(target_os = "none"))]
static mut HOST_DEFERRED_REMOVAL_LIST: *mut CallbackList = core::ptr::null_mut();
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
unsafe fn callback_globals() -> (bool, *mut CallbackList, *mut CallbackList, *mut PosixMutex) {
    (
        read_volatile(CALLBACK_DISPATCH_ACTIVE_ADDRESS as *const u8) != 0,
        CALLBACK_LIST_ADDRESS as *mut CallbackList,
        DEFERRED_REMOVAL_LIST_ADDRESS as *mut CallbackList,
        CALLBACK_MUTEX_ADDRESS as *mut PosixMutex,
    )
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn callback_globals() -> (bool, *mut CallbackList, *mut CallbackList, *mut PosixMutex) {
    (
        read_volatile(addr_of!(HOST_CALLBACK_DISPATCH_ACTIVE)) != 0,
        read_volatile(addr_of!(HOST_CALLBACK_LIST)),
        read_volatile(addr_of!(HOST_DEFERRED_REMOVAL_LIST)),
        addr_of_mut!(HOST_CALLBACK_MUTEX),
    )
}

/// Removes `callback` from the global callback list, or defers that removal
/// while the list is being dispatched.
///
/// Original: `FUN_082928d8` at `0x082928d8` (172 bytes; **10 direct `bl`
/// callers: 6 unconditional, 2 `bleq`, 2 `blne**`). The callback is an opaque
/// firmware word and zero is a searchable value; the original validates
/// neither it nor the global list state.
///
/// # Safety
///
/// On target, the fixed global list state must retain its retail layout. On
/// host, callers must install a valid list fixture and
/// [`GLOBAL_CALLBACK_UNREGISTER_OPS`]. Node links are 32-bit target pointers
/// and must be valid until this call returns.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_callback_unregister(callback: u32) {
    let (dispatch_active, callback_list, deferred_removals, mutex) = callback_globals();
    let _ = posix_mutex_lock(mutex);

    if dispatch_active {
        (unregister_ops().append_deferred)(deferred_removals, addr_of!(callback));
    } else {
        let sentinel = (*callback_list).sentinel;
        let mut cursor = (*(sentinel as usize as *const CallbackNode)).next;
        loop {
            let end = (*callback_list).sentinel;
            if not_equal_deref(addr_of!(cursor), addr_of!(end)) == 0 {
                break;
            }

            let node = cursor as usize as *mut CallbackNode;
            if (*node).callback == callback {
                let mut next = 0;
                (unregister_ops().erase)(addr_of_mut!(next), callback_list, addr_of!(cursor));
                break;
            }
            cursor = (*node).next;
        }
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
    const DEFERRED_LIST_OFFSET: usize = 0x40;
    const SENTINEL_OFFSET: usize = 0x100;
    const FIRST_NODE_OFFSET: usize = 0x140;
    const SECOND_NODE_OFFSET: usize = 0x180;
    const THIRD_NODE_OFFSET: usize = 0x1c0;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::GLOBAL_CALLBACK_UNREGISTER, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    static mut ERASE_CALLS: u32 = 0;
    static mut ERASED_CALLBACK: u32 = 0;
    static mut ERASED_LIST: usize = 0;
    static mut DEFER_CALLS: u32 = 0;
    static mut DEFERRED_CALLBACK: u32 = 0;
    static mut DEFERRED_LIST: usize = 0;

    fn try_fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock();
        (*FIXTURE).map(|base| (base as *mut u8, guard))
    }

    unsafe fn list(base: *mut u8) -> *mut CallbackList {
        base.cast::<CallbackList>()
    }

    unsafe fn deferred_list(base: *mut u8) -> *mut CallbackList {
        base.add(DEFERRED_LIST_OFFSET).cast::<CallbackList>()
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
        deferred_list(base).write(CallbackList {
            _unknown_00: 0,
            _free_node: 0,
            _unknown_08: 0,
            _unknown_0c: 0,
            sentinel: 0,
            _count: 0,
        });
        HOST_CALLBACK_DISPATCH_ACTIVE = 0;
        HOST_CALLBACK_LIST = list(base);
        HOST_DEFERRED_REMOVAL_LIST = deferred_list(base);
        HOST_CALLBACK_MUTEX = PosixMutex {
            magic: 0,
            owner: 0,
            reserved_08: 0,
            attr_flags: 0,
            reserved_10: 0,
            recursion: 0,
            sem_handle: 0,
        };
        ERASE_CALLS = 0;
        ERASED_CALLBACK = 0;
        ERASED_LIST = 0;
        DEFER_CALLS = 0;
        DEFERRED_CALLBACK = 0;
        DEFERRED_LIST = 0;
        GLOBAL_CALLBACK_UNREGISTER_OPS = GlobalCallbackUnregisterOps {
            erase: erase_fixture_node,
            append_deferred: record_deferred_callback,
        };
    }

    unsafe extern "C" fn erase_fixture_node(
        next: *mut u32,
        callback_list: *mut CallbackList,
        cursor: *const u32,
    ) {
        let removed = cursor.read() as usize as *mut CallbackNode;
        let following = (*removed).next as usize as *mut CallbackNode;
        let preceding = (*removed)._previous as usize as *mut CallbackNode;
        (*preceding).next = (*removed).next;
        (*following)._previous = (*removed)._previous;
        (*callback_list)._count -= 1;
        next.write((*removed).next);
        ERASE_CALLS += 1;
        ERASED_CALLBACK = (*removed).callback;
        ERASED_LIST = callback_list as usize;
    }

    unsafe extern "C" fn record_deferred_callback(
        callback_list: *mut CallbackList,
        callback: *const u32,
    ) {
        DEFER_CALLS += 1;
        DEFERRED_CALLBACK = callback.read();
        DEFERRED_LIST = callback_list as usize;
    }

    #[test]
    fn removes_only_the_first_matching_callback_and_unlocks() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("global_callback_unregister");
            return;
        };
        unsafe {
            build_list(base, [0x11, 0x22, 0x22]);
            global_callback_unregister(0x22);
            assert_eq!(ERASE_CALLS, 1);
            assert_eq!(ERASED_CALLBACK, 0x22);
            assert_eq!(ERASED_LIST, list(base) as usize);
            assert_eq!((*list(base))._count, 2);
            assert_eq!((*node(base, FIRST_NODE_OFFSET)).next, node(base, THIRD_NODE_OFFSET) as u32);
            assert_eq!((*node(base, THIRD_NODE_OFFSET))._previous, node(base, FIRST_NODE_OFFSET) as u32);
            assert_eq!((*node(base, THIRD_NODE_OFFSET)).callback, 0x22, "the later duplicate remains registered");
            assert_eq!(HOST_CALLBACK_MUTEX.owner, 0, "the ignored lock status cannot skip unlock");
            assert_eq!(HOST_CALLBACK_MUTEX.recursion, 0);
            assert_eq!(DEFER_CALLS, 0);
        }
    }

    #[test]
    fn missing_callback_leaves_the_circular_list_unchanged() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("global_callback_unregister");
            return;
        };
        unsafe {
            build_list(base, [0, 1, u32::MAX]);
            global_callback_unregister(0x7fff_ffff);
            assert_eq!(ERASE_CALLS, 0);
            assert_eq!((*list(base))._count, 3);
            assert_eq!((*node(base, SENTINEL_OFFSET)).next, node(base, FIRST_NODE_OFFSET) as u32);
            assert_eq!((*node(base, THIRD_NODE_OFFSET)).next, node(base, SENTINEL_OFFSET) as u32);
            assert_eq!(DEFER_CALLS, 0);
        }
    }

    #[test]
    fn active_dispatch_defers_zero_without_reading_the_main_list() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("global_callback_unregister");
            return;
        };
        unsafe {
            build_list(base, [1, 2, 3]);
            HOST_CALLBACK_DISPATCH_ACTIVE = 1;
            (*list(base)).sentinel = 0;
            global_callback_unregister(0);
            assert_eq!(ERASE_CALLS, 0);
            assert_eq!(DEFER_CALLS, 1);
            assert_eq!(DEFERRED_CALLBACK, 0, "zero is forwarded as a callback word");
            assert_eq!(DEFERRED_LIST, deferred_list(base) as usize);
            assert_eq!(HOST_CALLBACK_MUTEX.owner, 0);
        }
    }
}
