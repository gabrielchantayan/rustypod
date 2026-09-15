//! Port of the block-manager client's single-region acquisition op.
//!
//! `client_take_region` — original: `FUN_081fc7d8` @ 0x081fc7d8
//! (**172 bytes**, 0x081fc7d8..0x081fc884; **9 plain `bl`, 0 predicated
//! `bl`**, binary-decoded from osos.dec). Under the client mutex at +0x24,
//! it admits an acquisition when either the 0x40000 state bit is clear and
//! produced < expected, or it is set and produced != head. Admission calls
//! the block manager's single-region hand-out @ 0x0818b028; rejection
//! constructs a temporary region, copy-constructs `dst`, then destroys it.
//!
//! # Deliberate deviations
//!
//! The unported manager hand-out and the region ctor/copy/dtor triple dispatch
//! through [`CLIENT_TAKE_REGION_OPS`] (indirect `blx` instead of direct `bl`).
//! Wired defaults are the existing region ports; manager hand-out is a no-op
//! before block-manager initialization. Client fields are literal target-width
//! words, read unaligned so host layout cannot change target offsets.

use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::heap::client_erase::CLIENT_MUTEX_OFFSET;
use crate::util::state_flags::state_flags_contain;

const HEADROOM_MASK: u32 = 0x40000;
const CLIENT_MANAGER_OFFSET: usize = 0x4;
const CLIENT_STATE_OFFSET: usize = 0x8;
const CLIENT_PRODUCED_OFFSET: usize = 0x18;
const CLIENT_EXPECTED_OFFSET: usize = 0x1c;
const CLIENT_HEAD_OFFSET: usize = 0x50;
type RegionTemp = [usize; 5];

#[inline(always)]
unsafe fn word(object: *mut u8, offset: usize) -> u32 { (object.add(offset) as *const u32).read_unaligned() }
#[inline(always)]
unsafe fn ptr_word(object: *mut u8, offset: usize) -> *mut u8 { word(object, offset) as usize as *mut u8 }

#[derive(Clone, Copy)]
pub struct ClientTakeRegionOps {
    /// Block-manager single-region hand-out @ 0x0818b028 `(dst, manager, client + 8)`.
    pub manager_take_one: unsafe extern "C" fn(dst: *mut u8, manager: *mut u8, state: *mut u8),
    /// Region default constructor @ 0x082804b8 `(dst)`.
    pub region_default: unsafe extern "C" fn(dst: *mut u8),
    /// Region copy constructor @ 0x08280464 `(dst, src)`.
    pub region_copy: unsafe extern "C" fn(dst: *mut u8, src: *const u8),
    /// Region destructor @ 0x082804fc `(obj)`.
    pub region_destroy: unsafe extern "C" fn(obj: *mut u8),
}

unsafe extern "C" fn stub_manager_take_one(_dst: *mut u8, _manager: *mut u8, _state: *mut u8) {}
unsafe extern "C" fn default_region_default(dst: *mut u8) { crate::heap::block_region::region_elem_default_construct(dst); }
unsafe extern "C" fn default_region_copy(dst: *mut u8, src: *const u8) { crate::heap::block_region::region_elem_copy_construct(dst, src); }
unsafe extern "C" fn default_region_destroy(obj: *mut u8) { crate::heap::block_region::region_elem_destroy(obj); }

pub(crate) const DEFAULT_CLIENT_TAKE_REGION_OPS: ClientTakeRegionOps = ClientTakeRegionOps {
    manager_take_one: stub_manager_take_one,
    region_default: default_region_default,
    region_copy: default_region_copy,
    region_destroy: default_region_destroy,
};
pub static mut CLIENT_TAKE_REGION_OPS: ClientTakeRegionOps = DEFAULT_CLIENT_TAKE_REGION_OPS;

macro_rules! op { ($field:ident) => { unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CLIENT_TAKE_REGION_OPS.$field)) } }; }
macro_rules! mutex_op { ($field:ident) => { unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) } }; }

/// client_take_region — original: `FUN_081fc7d8` @ 0x081fc7d8 (172 bytes).
///
/// Acquires one region descriptor into `dst` when the client's counters admit
/// it; otherwise constructs, copies, and destroys a default temporary. The
/// client mutex brackets both paths.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn client_take_region(dst: *mut u8, client: *mut u8) {
    let mutex = client.add(CLIENT_MUTEX_OFFSET);
    (mutex_op!(lock))(mutex);
    let flagged = state_flags_contain(client, HEADROOM_MASK) != 0;
    let unavailable = if !flagged {
        word(client, CLIENT_PRODUCED_OFFSET) >= word(client, CLIENT_EXPECTED_OFFSET)
    } else {
        word(client, CLIENT_HEAD_OFFSET) == word(client, CLIENT_PRODUCED_OFFSET)
    };
    if unavailable {
        let mut temp: RegionTemp = [0; 5];
        let temp = temp.as_mut_ptr().cast::<u8>();
        (op!(region_default))(temp);
        (op!(region_copy))(dst, temp);
        (op!(region_destroy))(temp);
    } else {
        (op!(manager_take_one))(dst, ptr_word(client, CLIENT_MANAGER_OFFSET), client.add(CLIENT_STATE_OFFSET));
    }
    (mutex_op!(unlock))(mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::block_region::{RegionMutexOps, DEFAULT_REGION_MUTEX_OPS};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ev { Lock(usize), Take(usize, usize, usize), Default, Copy(usize), Destroy, Unlock(usize) }
    static mut EVENTS: Vec<Ev> = Vec::new();
    fn push(ev: Ev) { unsafe { (*addr_of_mut!(EVENTS)).push(ev) } }
    fn events() -> Vec<Ev> { unsafe { (*addr_of!(EVENTS)).clone() } }
    unsafe extern "C" fn lock(m: *mut u8) -> u32 { push(Ev::Lock(m as usize)); 0 }
    unsafe extern "C" fn unlock(m: *mut u8) -> u32 { push(Ev::Unlock(m as usize)); 0 }
    unsafe extern "C" fn take(dst: *mut u8, manager: *mut u8, state: *mut u8) { dst.write(0xa5); push(Ev::Take(dst as usize, manager as usize, state as usize)); }
    unsafe extern "C" fn default(_: *mut u8) { push(Ev::Default); }
    unsafe extern "C" fn copy(dst: *mut u8, _: *const u8) { dst.write(0x5a); push(Ev::Copy(dst as usize)); }
    unsafe extern "C" fn destroy(_: *mut u8) { push(Ev::Destroy); }
    fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(EVENTS)).clear();
            addr_of_mut!(CLIENT_TAKE_REGION_OPS).write(ClientTakeRegionOps { manager_take_one: take, region_default: default, region_copy: copy, region_destroy: destroy });
            addr_of_mut!(REGION_MUTEX_OPS).write(RegionMutexOps { lock, unlock });
        }
        guard
    }
    fn restore(guard: MutexGuard<'static, ()>) { unsafe { addr_of_mut!(CLIENT_TAKE_REGION_OPS).write(DEFAULT_CLIENT_TAKE_REGION_OPS); addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS); } drop(guard); }
    #[repr(align(4))] struct Client([u8; 0x60]);
    unsafe fn set_word(client: *mut u8, offset: usize, value: u32) { (client.add(offset) as *mut u32).write_unaligned(value); }
    #[test]
    fn acquires_when_unflagged_counters_have_headroom() {
        let guard = install(); unsafe {
            let mut client = Client([0; 0x60]); let client = client.0.as_mut_ptr();
            set_word(client, CLIENT_MANAGER_OFFSET, 0x1234_5000); set_word(client, CLIENT_PRODUCED_OFFSET, 3); set_word(client, CLIENT_EXPECTED_OFFSET, 4);
            let mut dst = [0; 40]; client_take_region(dst.as_mut_ptr(), client);
            assert_eq!(dst[0], 0xa5);
            assert_eq!(events(), std::vec![Ev::Lock(client.add(0x24) as usize), Ev::Take(dst.as_mut_ptr() as usize, 0x1234_5000, client.add(8) as usize), Ev::Unlock(client.add(0x24) as usize)]);
        } restore(guard);
    }
    #[test]
    fn defaults_at_unflagged_and_flagged_boundaries() {
        let guard = install(); unsafe {
            let mut client = Client([0; 0x60]); let client = client.0.as_mut_ptr();
            for (flags, produced, expected, head) in [(0, 4, 4, 9), (HEADROOM_MASK, 4, 9, 4)] {
                (*addr_of_mut!(EVENTS)).clear(); set_word(client, 0x44, flags); set_word(client, CLIENT_PRODUCED_OFFSET, produced); set_word(client, CLIENT_EXPECTED_OFFSET, expected); set_word(client, CLIENT_HEAD_OFFSET, head);
                let mut dst = [0; 40]; client_take_region(dst.as_mut_ptr(), client); assert_eq!(dst[0], 0x5a);
                assert_eq!(events(), std::vec![Ev::Lock(client.add(0x24) as usize), Ev::Default, Ev::Copy(dst.as_mut_ptr() as usize), Ev::Destroy, Ev::Unlock(client.add(0x24) as usize)]);
            }
        } restore(guard);
    }
}
