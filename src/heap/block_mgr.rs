//! Ports of the block-manager global queries used by the aligned-block
//! pool allocator (heap/pool.rs) and the block-deque fill
//! (heap/block_deque.rs):
//!
//! - `block_manager_get` — original: `FUN_0818ae48` @ 0x0818ae48
//!   (12 bytes; 14 `bl` call sites): `ldr r0, =0x089cb1b4;
//!   ldr r0, [r0]; bx lr` — returns the block-manager object pointer.
//! - `region_block_size` — original: `FUN_0818a364` @ 0x0818a364
//!   (24 bytes; 16 `bl` call sites + the alias thunk `b` @ 0x081a7a9c,
//!   1 caller): reads the same global; NULL manager returns 0, otherwise
//!   the per-region block size word at manager + 0x30.
//!
//! The global @ 0x089cb1b4 holds the "AMBlockManagerThread" object
//! (see pool.rs's alignment-table provenance note: the whole 0x089cb1xx
//! page is re-initialized at runtime — the decrypted image shows UI
//! strings there). Until the block-manager thread itself is ported,
//! nothing in this crate writes the pointer; the deviation below keeps
//! both queries testable and faithful.
//!
//! Deviation (by necessity, same as types.rs's `DEFAULT_HEAP` for
//! 0x089ca638): the global word is modeled as the crate static
//! [`BLOCK_MANAGER`] instead of living at 0x089cb1b4. It defaults to
//! NULL — exactly the pre-init state on device — so `region_block_size`
//! returns 0 and `block_manager_get` returns NULL until an install (or a
//! host test) stores the object pointer.

/// Byte offset of the per-region block size word in the block-manager
/// object (original: `ldrne r0, [r0, #0x30]`).
pub const BLOCK_SIZE_OFFSET: usize = 0x30;

/// The block-manager object pointer: original global word @ 0x089cb1b4
/// (see the module header for the modeling deviation). NULL until the
/// block-manager thread is up.
pub static mut BLOCK_MANAGER: *mut u8 = core::ptr::null_mut();

/// Reads the global. Volatile: the word is written at runtime (block
/// manager startup / host tests), and a build in which nothing writes it
/// must not constant-fold the NULL in.
#[inline(always)]
fn block_manager() -> *mut u8 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BLOCK_MANAGER)) }
}

/// block_manager_get — original: `FUN_0818ae48` @ 0x0818ae48 (12 bytes).
///
/// Returns the block-manager object pointer (NULL before the manager
/// thread exists).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn block_manager_get() -> *mut u8 {
    block_manager()
}

/// region_block_size — original: `FUN_0818a364` @ 0x0818a364 (24 bytes;
/// alias thunk `b` @ 0x081a7a9c).
///
/// Per-region block size: the word at manager + 0x30, or 0 when no block
/// manager exists.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn region_block_size() -> u32 {
    let mgr = block_manager();
    if mgr.is_null() {
        return 0;
    }
    (mgr.add(BLOCK_SIZE_OFFSET) as *const u32).read()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that swap the global manager pointer.
    static MGR_LOCK: Mutex<()> = Mutex::new(());

    /// Fake block-manager object: big enough to hold the +0x30 word.
    #[repr(align(4))]
    struct FakeManager([u8; 0x40]);
    static mut FAKE_MGR: FakeManager = FakeManager([0; 0x40]);

    /// Locks the global and installs the fake manager with the given
    /// block-size word.
    fn install_manager(block_size: u32) -> MutexGuard<'static, ()> {
        let guard = MGR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mgr = core::ptr::addr_of_mut!(FAKE_MGR) as *mut u8;
            (mgr.add(BLOCK_SIZE_OFFSET) as *mut u32).write(block_size);
            BLOCK_MANAGER = mgr;
        }
        guard
    }

    /// Restores the NULL default. Call before dropping the guard.
    fn clear_manager() {
        unsafe { BLOCK_MANAGER = core::ptr::null_mut() };
    }

    #[test]
    fn no_manager_returns_zero_size_and_null() {
        let _guard = MGR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_manager();
        unsafe {
            assert_eq!(region_block_size(), 0);
            assert!(block_manager_get().is_null());
        }
    }

    #[test]
    fn size_comes_from_manager_plus_0x30() {
        let _guard = install_manager(0x8_0000);
        unsafe {
            assert_eq!(region_block_size(), 0x8_0000);
            assert_eq!(
                block_manager_get(),
                core::ptr::addr_of_mut!(FAKE_MGR) as *mut u8
            );
        }
        clear_manager();
    }

    #[test]
    fn zero_size_word_reads_back_as_zero_with_a_manager() {
        // A present manager with a 0 word is distinguishable from "no
        // manager" only by block_manager_get — the size query returns 0
        // either way, exactly like the original.
        let _guard = install_manager(0);
        unsafe {
            assert_eq!(region_block_size(), 0);
            assert!(!block_manager_get().is_null());
        }
        clear_manager();
    }
}
