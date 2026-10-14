//! `list_release_chain_destroy` — retailOS `FUN_083dd16c` @ `0x083dd16c`.
//!
//! Raw ARM is exactly 60 bytes, from `push {r4,lr}` at `0x083dd16c` through
//! `pop {r4,pc}` at `0x083dd1a4`; `0x083dd1a8` starts the next function.
//! Whole-image ARM decoding finds two plain inbound `bl` calls (`0x0821397c`,
//! `0x08213984`) and one predicated `blne` call (`0x083cadec`). The function
//! skips an empty release chain; otherwise it calls the unresolved node-chain
//! preparer, relinks the resulting chain head into the release sentinel, then
//! calls the ported word-pair list pool release. Deliberate deviations: the
//! preparer remains an explicit target-address boundary; pool release uses
//! the Rust port directly by default.

const RELEASE_CHAIN_HEAD_WORD: usize = 1;
const RELEASE_SENTINEL_WORD: usize = 4;

/// Direct-callee boundaries used by [`list_release_chain_destroy`].
#[derive(Clone, Copy)]
pub struct ListReleaseChainDestroyOps {
    /// `FUN_083dcf94(this)`: prepares the node chain for release.
    pub prepare_release_chain: unsafe extern "C" fn(*mut u8),
    /// Ported word-pair list pool release (`0x083dcf40`).
    pub release_chain: unsafe extern "C" fn(*mut u8),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_prepare_release_chain(this: *mut u8) {
    let prepare: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x083d_cf94usize) };
    unsafe { prepare(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare_release_chain(_this: *mut u8) {
    panic!("list_release_chain_destroy requires unresolved FUN_083dcf94")
}

#[cfg(target_os = "none")]
pub const DEFAULT_LIST_RELEASE_CHAIN_DESTROY_OPS: ListReleaseChainDestroyOps = ListReleaseChainDestroyOps {
    prepare_release_chain: firmware_prepare_release_chain,
    release_chain: super::word_pair_list_pool_release::word_pair_list_pool_release,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_LIST_RELEASE_CHAIN_DESTROY_OPS: ListReleaseChainDestroyOps = ListReleaseChainDestroyOps {
    prepare_release_chain: missing_prepare_release_chain,
    release_chain: super::word_pair_list_pool_release::word_pair_list_pool_release,
};

/// Active unresolved direct-callee boundary. Host tests install recorders.
pub static mut LIST_RELEASE_CHAIN_DESTROY_OPS: ListReleaseChainDestroyOps =
    DEFAULT_LIST_RELEASE_CHAIN_DESTROY_OPS;

#[inline(always)]
unsafe fn destroy_ops() -> ListReleaseChainDestroyOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LIST_RELEASE_CHAIN_DESTROY_OPS)) }
}

#[inline(always)]
unsafe fn read_word(base: *mut u8, word: usize) -> u32 {
    unsafe { base.cast::<u32>().add(word).read() }
}

#[inline(always)]
unsafe fn write_word(base: *mut u8, word: usize, value: u32) {
    unsafe { base.cast::<u32>().add(word).write(value) }
}

/// Releases a prepared node chain and returns `this`.
///
/// # Safety
/// `this` must address the observed target-word layout through word four. When
/// its sentinel word is nonzero, both selected direct-callee boundaries must
/// accept `this` and preserve the target ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_release_chain_destroy")]
#[inline(never)]
pub unsafe extern "C" fn list_release_chain_destroy(this: *mut u8) -> *mut u8 {
    if unsafe { read_word(this, RELEASE_SENTINEL_WORD) } != 0 {
        let ops = unsafe { destroy_ops() };
        unsafe { (ops.prepare_release_chain)(this) };

        let sentinel = unsafe { read_word(this, RELEASE_SENTINEL_WORD) };
        let head = unsafe { read_word(this, RELEASE_CHAIN_HEAD_WORD) };
        unsafe { write_word(sentinel as usize as *mut u8, 0, head) };
        unsafe { write_word(this, RELEASE_CHAIN_HEAD_WORD, sentinel) };

        unsafe { (ops.release_chain)(this) };
    }
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::vec::Vec;
    use std::vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: Option<Vec<&'static str>> = None;
    static mut REPLACEMENT_SENTINEL: u32 = 0;
    static mut REPLACEMENT_HEAD: u32 = 0;

    unsafe extern "C" fn recording_prepare(this: *mut u8) {
        unsafe {
            EVENTS.as_mut().unwrap().push("prepare");
            write_word(this, RELEASE_SENTINEL_WORD, REPLACEMENT_SENTINEL);
            write_word(this, RELEASE_CHAIN_HEAD_WORD, REPLACEMENT_HEAD);
        }
    }

    unsafe extern "C" fn recording_release(_this: *mut u8) {
        unsafe { EVENTS.as_mut().unwrap().push("release") }
    }

    const RECORDING_OPS: ListReleaseChainDestroyOps = ListReleaseChainDestroyOps {
        prepare_release_chain: recording_prepare,
        release_chain: recording_release,
    };

    #[test]
    fn empty_chain_returns_without_calling_boundaries() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_RELEASE_CHAIN_DESTROY, 0x100) else {
            return;
        };
        unsafe {
            EVENTS = Some(Vec::new());
            LIST_RELEASE_CHAIN_DESTROY_OPS = RECORDING_OPS;
            write_word(slab, RELEASE_CHAIN_HEAD_WORD, 0xdead_beef);
            write_word(slab, RELEASE_SENTINEL_WORD, 0);
            assert_eq!(list_release_chain_destroy(slab), slab);
            assert_eq!(read_word(slab, RELEASE_CHAIN_HEAD_WORD), 0xdead_beef);
            assert!(EVENTS.as_ref().unwrap().is_empty());
            LIST_RELEASE_CHAIN_DESTROY_OPS = DEFAULT_LIST_RELEASE_CHAIN_DESTROY_OPS;
            EVENTS = None;
        }
    }

    #[test]
    fn populated_chain_reloads_preparer_updates_before_relinking_and_releasing() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_RELEASE_CHAIN_DESTROY, 0x200) else {
            return;
        };
        let object = slab;
        let sentinel = unsafe { slab.add(0x100) };
        unsafe {
            EVENTS = Some(Vec::new());
            REPLACEMENT_SENTINEL = sentinel as usize as u32;
            REPLACEMENT_HEAD = 0xa5a5_5a5a;
            LIST_RELEASE_CHAIN_DESTROY_OPS = RECORDING_OPS;
            write_word(object, RELEASE_CHAIN_HEAD_WORD, 0x1111_2222);
            write_word(object, RELEASE_SENTINEL_WORD, 0x3333_4444);
            assert_eq!(list_release_chain_destroy(object), object);
            assert_eq!(read_word(sentinel, 0), REPLACEMENT_HEAD);
            assert_eq!(read_word(object, RELEASE_CHAIN_HEAD_WORD), REPLACEMENT_SENTINEL);
            assert_eq!(EVENTS.as_ref().unwrap(), &vec!["prepare", "release"]);
            LIST_RELEASE_CHAIN_DESTROY_OPS = DEFAULT_LIST_RELEASE_CHAIN_DESTROY_OPS;
            EVENTS = None;
        }
    }
}
