//! Port of the block-manager client *registration* — the verdict
//! `pool_client_attach` (heap/pool_client.rs) returns and
//! `block_deque_fill` (heap/block_deque.rs) gates on:
//!
//! - `client_register` — original: `FUN_081eff38` @ 0x081eff38 (60
//!   bytes; 1 `bl` call site @ 0x081efd30, inside `pool_client_attach`,
//!   binary-verified). Reads the object's two-level client ref at +0x4
//!   through the 0x08262b1c copy of `handle_deref_or_null`
//!   (cxx/handle.rs — the one copy outside the C++ block, byte-identical
//!   to the other 21): a live handle means the client is already
//!   registered, and the preset verdict 1 (`mov r5, #0x1` ahead of the
//!   test, kept by the `bne`) is returned untouched. Otherwise the
//!   block-manager object (`block_manager_get` @ 0x0818ae48,
//!   heap/block_mgr.rs — real port) is handed the registration node at
//!   +0x2c, a zero word in r2, and the +0x4 ref slot —
//!   `0x0818a630(mgr, this+0x2c, 0, this+0x4)` — which links the node
//!   into the manager's client list and installs the two-level ref
//!   every later client call reads through `handle_deref_or_null`. The
//!   callee's return is the verdict.
//!
//! # Deviations
//!
//! - The manager-side registration @ 0x0818a630 is unported
//!   block-manager machinery (the ledger's reserve/headroom/populate/
//!   erase cluster), so it dispatches through
//!   [`MANAGER_CLIENT_REGISTER`] (house ops-slot pattern). The default
//!   reports 0 — the no-registration verdict, which is what keeps
//!   `pool_client_attach`'s wired defaults refusing without a manager
//!   (the state `block_deque_fill`'s gate needs). Indirect `blx` in
//!   place of `bl`, as throughout the heap cluster.
//! - The zero word in r2 is a notification flag inside 0x0818a630
//!   (nonzero would `bl 0x0818a3b4(mgr, 0xa)` after the node is
//!   linked); it is 0 at this, the function's only, call site.
//! - The two ported callees are called directly:
//!   `handle_deref_or_null` is `#[inline(never)]` (the block_deque.rs
//!   `base_client` precedent — the call survives as a call), and
//!   `block_manager_get` is called directly everywhere else in the
//!   cluster (block_deque.rs's fill).

use crate::cxx::handle::handle_deref_or_null;
use crate::heap::block_deque::PoolBase;
use crate::heap::block_mgr::block_manager_get;
use crate::heap::pool_client::ClientNode;

/// Default manager-side registration: the block manager thread is not
/// ported, so no registration can happen — the verdict that makes
/// `pool_client_attach`'s wired defaults refuse (the pool_client.rs
/// `stub_client_register` contract this port replaces).
unsafe extern "C" fn stub_manager_client_register(
    _mgr: *mut u8,
    _node: *mut ClientNode,
    _flags: u32,
    _ref_slot: *mut *const *mut u8,
) -> i32 {
    0
}

/// The 0x0818a630 boundary (see the module-header deviation). Default:
/// the documented no-registration stub; host tests swap in recorders
/// and restore the default.
pub static mut MANAGER_CLIENT_REGISTER: unsafe extern "C" fn(
    mgr: *mut u8,
    node: *mut ClientNode,
    flags: u32,
    ref_slot: *mut *const *mut u8,
) -> i32 = stub_manager_client_register;

/// Reads the registration slot (volatile — same rationale as every
/// dispatch table: a build in which nothing swaps it must not
/// constant-fold the default in).
#[inline(always)]
fn manager_register() -> unsafe extern "C" fn(
    mgr: *mut u8,
    node: *mut ClientNode,
    flags: u32,
    ref_slot: *mut *const *mut u8,
) -> i32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MANAGER_CLIENT_REGISTER)) }
}

/// client_register — original: `FUN_081eff38` @ 0x081eff38 (60 bytes).
///
/// Registers the object's block-manager client: 1 when the two-level
/// ref at +0x4 already resolves to a live handle, otherwise the
/// manager-side registration verdict (0 with the wired defaults — no
/// block manager).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn client_register(this: *mut PoolBase) -> i32 {
    let ref_slot = core::ptr::addr_of!((*this).client_ref);
    // 0x08262b1c on this+0x4: a live handle means already registered
    // (the preset r5 = 1 the `bne` keeps).
    if !handle_deref_or_null(ref_slot).is_null() {
        return 1;
    }
    let mgr = block_manager_get();
    (manager_register())(
        mgr,
        core::ptr::addr_of_mut!((*this).node),
        0,
        ref_slot as *mut *const *mut u8,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes this module's slot swaps (and takes block_mgr's lock
    /// before touching its global — the queue_wait.rs two-lock order;
    /// no other module takes both, so no cycle).
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Recorded manager-side calls: (mgr, node, flags, ref_slot).
    static mut CALLS: Vec<(usize, usize, u32, usize)> = Vec::new();
    /// Verdict the recorder hands back.
    static mut REGISTER_RC: i32 = 0;

    unsafe extern "C" fn mock_manager_client_register(
        mgr: *mut u8,
        node: *mut ClientNode,
        flags: u32,
        ref_slot: *mut *const *mut u8,
    ) -> i32 {
        (*addr_of_mut!(CALLS)).push((mgr as usize, node as usize, flags, ref_slot as usize));
        *addr_of!(REGISTER_RC)
    }

    fn calls() -> Vec<(usize, usize, u32, usize)> {
        unsafe { (*addr_of!(CALLS)).clone() }
    }

    /// Zeroed base object, like pool_client.rs's tests.
    fn zeroed_base() -> std::boxed::Box<PoolBase> {
        std::boxed::Box::new(unsafe { core::mem::zeroed::<PoolBase>() })
    }

    /// Installs the recorder with the given verdict, NULLs the
    /// block-manager global, and takes both locks (this module's, then
    /// block_mgr's).
    fn install(rc: i32) -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mgr_guard = crate::heap::block_mgr::tests::MGR_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(CALLS)).clear();
            *addr_of_mut!(REGISTER_RC) = rc;
            addr_of_mut!(MANAGER_CLIENT_REGISTER).write(mock_manager_client_register);
            addr_of_mut!(crate::heap::block_mgr::BLOCK_MANAGER).write(core::ptr::null_mut());
        }
        (guard, mgr_guard)
    }

    /// Restores the defaults; the guards drop last (house pattern).
    fn restore(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe {
            addr_of_mut!(MANAGER_CLIENT_REGISTER).write(stub_manager_client_register);
            addr_of_mut!(crate::heap::block_mgr::BLOCK_MANAGER).write(core::ptr::null_mut());
        }
        drop(guards);
    }

    /// A two-level client ref in caller-owned cells, like the +0x4
    /// slot after a real registration.
    struct RefCells {
        slot: *mut u8,
        handle: u8,
    }

    impl RefCells {
        fn new() -> Self {
            RefCells {
                slot: core::ptr::null_mut(),
                handle: 0,
            }
        }
        /// Points the object's +0x4 at a cell holding a live handle.
        unsafe fn install_live(&mut self, this: *mut PoolBase) {
            self.slot = addr_of_mut!(self.handle);
            (*this).client_ref = addr_of_mut!(self.slot) as *const *mut u8;
        }
        /// Points the object's +0x4 at a cell holding NULL (an empty
        /// middle pointer — not a live handle).
        unsafe fn install_empty(&mut self, this: *mut PoolBase) {
            self.slot = core::ptr::null_mut();
            (*this).client_ref = addr_of_mut!(self.slot) as *const *mut u8;
        }
    }

    #[test]
    fn a_live_handle_returns_one_without_calling_the_manager() {
        let guards = install(0);
        unsafe {
            let mut base = zeroed_base();
            let this = &mut *base as *mut PoolBase;
            let mut cells = RefCells::new();
            cells.install_live(this);

            assert_eq!(client_register(this), 1, "already registered");
            assert!(calls().is_empty(), "no manager-side registration");
        }
        restore(guards);
    }

    #[test]
    fn an_empty_middle_pointer_is_not_a_live_handle() {
        let guards = install(1);
        unsafe {
            let mut base = zeroed_base();
            let this = &mut *base as *mut PoolBase;
            let mut cells = RefCells::new();
            cells.install_empty(this);

            assert_eq!(client_register(this), 1, "registers afresh");
            assert_eq!(calls().len(), 1, "the middle NULL falls through");
        }
        restore(guards);
    }

    #[test]
    fn an_empty_ref_registers_through_the_manager_and_returns_its_verdict() {
        let guards = install(1);
        unsafe {
            let mgr = 0x089c_b1c0usize as *mut u8;
            addr_of_mut!(crate::heap::block_mgr::BLOCK_MANAGER).write(mgr);
            let mut base = zeroed_base();
            let this = &mut *base as *mut PoolBase;

            assert_eq!(client_register(this), 1);

            assert_eq!(
                calls(),
                std::vec![(
                    mgr as usize,
                    addr_of_mut!((*this).node) as usize,
                    0,
                    addr_of!((*this).client_ref) as usize,
                )],
                "mgr from the global, node +0x2c, zero flags, ref slot +0x4"
            );
        }
        restore(guards);
    }

    #[test]
    fn the_verdict_passes_through_untouched() {
        let guards = install(0);
        unsafe {
            let mut base = zeroed_base();
            let this = &mut *base as *mut PoolBase;

            assert_eq!(client_register(this), 0, "refused registration");
            *addr_of_mut!(REGISTER_RC) = -1;
            assert_eq!(client_register(this), -1, "even a negative verdict");
            *addr_of_mut!(REGISTER_RC) = 7;
            assert_eq!(client_register(this), 7, "and any other code");
        }
        restore(guards);
    }

    #[test]
    fn the_wired_defaults_report_no_registration() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mgr_guard = crate::heap::block_mgr::tests::MGR_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            addr_of_mut!(MANAGER_CLIENT_REGISTER).write(stub_manager_client_register);
            addr_of_mut!(crate::heap::block_mgr::BLOCK_MANAGER).write(core::ptr::null_mut());
            let mut base = zeroed_base();
            let this = &mut *base as *mut PoolBase;

            assert_eq!(client_register(this), 0, "no block manager, no verdict");
        }
        drop((guard, mgr_guard));
    }
}
