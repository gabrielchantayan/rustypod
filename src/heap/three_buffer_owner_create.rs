//! `three_buffer_owner_create` — allocate and initialize a three-buffer owner.
//!
//! Original: `FUN_0803df54` @ 0x0803df54 (52 bytes exactly,
//! 0x0803df54..0x0803df88; `FUN_0803df88` starts at the next word, with no
//! trailing literal pool). Decoding every ARM B/BL immediate in `osos.dec`
//! finds 3 direct call sites, all unconditional `bl` (0x0803f648,
//! 0x080c6e84, and 0x080c715c); there are no predicated forms. The body
//! itself issues exactly two `bl` calls: `traced_alloc` @ 0x08043c18 and the
//! sibling initializer `FUN_0803df28` (still unported).
//!
//! Algorithm: request 0x48 bytes through `traced_alloc(0x48, 0, 0)` and
//! return NULL when it fails (`movs`/`ldmiaeq`). On success, run the sibling
//! initializer `FUN_0803df28` on the block — it zeroes +0x00, memzeroes the
//! three embedded 0x14-byte buffers at +0x04, +0x18, and +0x2c through the
//! IRAM veneer 0x08037db8 (`memzero_aligned` @ 0x2200027c), and clears the
//! +0x44 flags word, leaving +0x40 untouched — then set `flags` (+0x44) to
//! [`FLAG_DELETE_THIS`](crate::heap::three_buffer_owner::FLAG_DELETE_THIS)
//! and return the block. The flag is what lets
//! [`three_buffer_owner_release`](crate::heap::three_buffer_owner::three_buffer_owner_release)
//! free the owner itself after its embedded buffers.
//!
//! Deliberate deviation: the still-unported sibling initializer
//! `FUN_0803df28` is reached through the replaceable, binary-verified
//! [`ThreeBufferOwnerOps`] boundary (the `registration_node_construct`
//! precedent). Its default reproduces the retail body's exact stores: word
//! +0x00 cleared, each embedded [`ReleasableBuffer`] zeroed over its full
//! 0x14 bytes, and +0x44 cleared — with +0x40 deliberately left alone,
//! matching the retail initializer.

use crate::drivers::ata_cmd::traced_alloc;
use crate::heap::releasable_buffer::ReleasableBuffer;
use crate::heap::three_buffer_owner::{ThreeBufferOwner, FLAG_DELETE_THIS};

/// Target allocation size of the owner.
const OWNER_SIZE: i32 = 0x48;

/// The unported sibling initializer's ABI (`FUN_0803df28` @ 0x0803df28).
#[derive(Clone, Copy)]
pub struct ThreeBufferOwnerOps {
    /// Initializes a fresh 0x48-byte owner: clears +0x00, zeroes the three
    /// embedded buffers, and clears +0x44; +0x40 is untouched.
    pub initialize: unsafe extern "C" fn(this: *mut ThreeBufferOwner),
}

/// Binary-verified default boundary for the unported initializer
/// `FUN_0803df28`: the same five-word zero fill over each embedded buffer
/// that its three `memzero_aligned(p, 0x14)` veneer calls produce, plus the
/// +0x00 and +0x44 clears. Volatile word stores keep LLVM from turning the
/// fills into a libc `memset` builtin.
unsafe extern "C" fn default_initialize(this: *mut ThreeBufferOwner) {
    unsafe {
        core::ptr::addr_of_mut!((*this).reserved).write_volatile(0);
        for buffer in [
            core::ptr::addr_of_mut!((*this).first),
            core::ptr::addr_of_mut!((*this).second),
            core::ptr::addr_of_mut!((*this).third),
        ] {
            core::ptr::addr_of_mut!((*buffer).data).write_volatile(0);
            core::ptr::addr_of_mut!((*buffer).reserved).write_volatile([0; 3]);
            core::ptr::addr_of_mut!((*buffer).flags).write_volatile(0);
        }
        core::ptr::addr_of_mut!((*this).flags).write_volatile(0);
    }
}

/// Default operations until `FUN_0803df28` has its own port.
pub const DEFAULT_THREE_BUFFER_OWNER_OPS: ThreeBufferOwnerOps = ThreeBufferOwnerOps {
    initialize: default_initialize,
};

/// Active boundary for the sibling owner initializer.
pub static mut THREE_BUFFER_OWNER_OPS: ThreeBufferOwnerOps = DEFAULT_THREE_BUFFER_OWNER_OPS;

#[inline(always)]
fn ops() -> ThreeBufferOwnerOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(THREE_BUFFER_OWNER_OPS)) }
}

/// (52 bytes; 3 `bl` direct call sites, all unconditional.)
///
/// Allocates a 0x48-byte owner through `traced_alloc(0x48, 0, 0)`; returns
/// NULL on allocation failure without any other store. On success the block
/// is initialized through the installed [`ThreeBufferOwnerOps`] boundary and
/// its +0x44 flags word is set to [`FLAG_DELETE_THIS`]. The returned pointer
/// names a writable, aligned [`ThreeBufferOwner`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn three_buffer_owner_create() -> *mut ThreeBufferOwner {
    let this = unsafe { traced_alloc(OWNER_SIZE, 0, 0) }.cast::<ThreeBufferOwner>();
    if this.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { (ops().initialize)(this) };
    unsafe { core::ptr::addr_of_mut!((*this).flags).write_volatile(FLAG_DELETE_THIS) };
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedAllocHooks, TRACED_ALLOC_HOOKS};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOC_CALLS: Vec<(i32, u32, u32)> = Vec::new();
    static mut ALLOC_RET: *mut u8 = core::ptr::null_mut();
    static mut INIT_CALLS: Vec<usize> = Vec::new();
    static mut FLAGS_AT_INIT: u32 = 0;

    unsafe extern "C" fn mock_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        unsafe {
            (*core::ptr::addr_of_mut!(ALLOC_CALLS)).push((size, tag1, tag2));
            core::ptr::read_volatile(core::ptr::addr_of!(ALLOC_RET))
        }
    }

    unsafe extern "C" fn recording_init(this: *mut ThreeBufferOwner) {
        unsafe {
            (*core::ptr::addr_of_mut!(INIT_CALLS)).push(this as usize);
            FLAGS_AT_INIT = core::ptr::addr_of!((*this).flags).read_volatile();
            core::ptr::addr_of_mut!((*this).flags).write_volatile(0x77);
        }
    }

    struct Restore {
        _alloc_guard: MutexGuard<'static, ()>,
        _guard: MutexGuard<'static, ()>,
        old_alloc: TracedAllocHooks,
    }

    fn install(block: *mut u8) -> Restore {
        let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let old_alloc = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_ALLOC_HOOKS));
            TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: mock_alloc, trace: None };
            core::ptr::addr_of_mut!(ALLOC_CALLS).write(Vec::new());
            core::ptr::addr_of_mut!(ALLOC_RET).write(block);
            core::ptr::addr_of_mut!(INIT_CALLS).write(Vec::new());
            core::ptr::addr_of_mut!(THREE_BUFFER_OWNER_OPS).write(DEFAULT_THREE_BUFFER_OWNER_OPS);
            Restore { _alloc_guard: alloc_guard, _guard: guard, old_alloc }
        }
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(THREE_BUFFER_OWNER_OPS).write(DEFAULT_THREE_BUFFER_OWNER_OPS);
                core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS).write_volatile(self.old_alloc);
            }
        }
    }

    /// Unique low-address mapping: the returned owner is a host pointer on
    /// 64-bit hosts, but the mock slab keeps the fixture off the real heap.
    fn try_block() -> Option<*mut u8> {
        static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::THREE_BUFFER_OWNER_CREATE, 0x1000)
                .map(|pointer| pointer as usize)
        });
        (*SLAB).map(|pointer| pointer as *mut u8)
    }

    fn fixture_unavailable() -> bool {
        try_block().is_none() && crate::testing::note_missing_u32_fixture("heap::three_buffer_owner_create")
    }

    #[test]
    fn allocation_failure_returns_null_without_initializing() {
        let _restore = install(core::ptr::null_mut());

        let created = unsafe { three_buffer_owner_create() };

        assert!(created.is_null());
        assert_eq!(unsafe { &*core::ptr::addr_of!(ALLOC_CALLS) }, &std::vec![(0x48, 0, 0)]);
        assert!(unsafe { &*core::ptr::addr_of!(INIT_CALLS) }.is_empty());
    }

    #[test]
    fn creates_a_zeroed_owner_with_delete_flag_and_untouched_trailing_word() {
        if fixture_unavailable() {
            return;
        }
        let block = try_block().unwrap();
        let _restore = install(block);
        unsafe { core::ptr::write_bytes(block, 0xa5, 0x48) };

        let created = unsafe { three_buffer_owner_create() };

        assert_eq!(created, block.cast::<ThreeBufferOwner>());
        assert_eq!(unsafe { &*core::ptr::addr_of!(ALLOC_CALLS) }, &std::vec![(0x48, 0, 0)]);
        let owner = unsafe { &*created };
        assert_eq!(owner.reserved, 0);
        for (name, buffer) in [
            ("first", &owner.first),
            ("second", &owner.second),
            ("third", &owner.third),
        ] {
            assert_eq!(buffer.data, 0, "{name}.data");
            assert_eq!(buffer.reserved, [0; 3], "{name}.reserved");
            assert_eq!(buffer.flags, 0, "{name}.flags");
        }
        assert_eq!(owner.trailing, 0xa5a5_a5a5, "retail initializer leaves +0x40 untouched");
        assert_eq!(owner.flags, FLAG_DELETE_THIS);
    }

    #[test]
    fn flags_are_written_after_the_initializer_runs() {
        if fixture_unavailable() {
            return;
        }
        let block = try_block().unwrap();
        let _restore = install(block);
        unsafe { core::ptr::write_bytes(block, 0, 0x48) };
        unsafe {
            core::ptr::addr_of_mut!(THREE_BUFFER_OWNER_OPS)
                .write(ThreeBufferOwnerOps { initialize: recording_init });
        }

        let created = unsafe { three_buffer_owner_create() };

        assert_eq!(created, block.cast::<ThreeBufferOwner>());
        assert_eq!(unsafe { &*core::ptr::addr_of!(INIT_CALLS) }, &std::vec![block as usize]);
        assert_eq!(unsafe { FLAGS_AT_INIT }, 0, "the initializer runs before the flags store");
        assert_eq!(unsafe { (*created).flags }, FLAG_DELETE_THIS, "create overwrites the initializer's flags");
    }
}
