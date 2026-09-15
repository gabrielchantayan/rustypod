//! `client_return_region` — retailOS `FUN_081fc784` at `0x081fc784`.
//!
//! Raw ARM establishes the true 84-byte extent `0x081fc784..0x081fc7d8`:
//! six plain `bl` instructions and no predicated `bl` instructions. Ghidra's
//! five `bl` call-site count is the inbound count; its C misses neither an
//! outbound call nor the boundary. Under the client mutex at +0x24, this
//! routine snapshots the returned region's block word (the returned handle's
//! inner cell at word 1, then word 3), releases the handle, hands that word to
//! the block manager, emits the drained/completion notifications, and unlocks.
//!
//! # Deliberate deviations
//!
//! The four non-mutex callees are not ported. Target builds call their resident
//! addresses; host tests supply them through [`CLIENT_RETURN_REGION_OPS`]. This
//! introduces indirect `blx` calls in place of retail direct `bl` calls.

use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::heap::client_erase::CLIENT_MUTEX_OFFSET;

const RETAIL_HANDLE_RELEASE: usize = 0x0828_03a8;
const RETAIL_HAND_BACK_BLOCK: usize = 0x081f_c124;
const RETAIL_NOTIFY_DRAINED: usize = 0x081f_bf1c;
const RETAIL_NOTIFY_COMPLETE: usize = 0x081f_c230;
const RETURNED_HANDLE_CELL_INDEX: usize = 1;
const CELL_BLOCK_INDEX: usize = 3;

pub type HandleRelease = unsafe extern "C" fn(*mut u8);
pub type HandBackBlock = unsafe extern "C" fn(*mut u8, *mut u32);
pub type NotifyDrained = unsafe extern "C" fn(*mut u8, u32);
pub type NotifyComplete = unsafe extern "C" fn(*mut u8);

#[derive(Clone, Copy)]
pub struct ClientReturnRegionOps {
    pub release_handle: HandleRelease,
    pub hand_back_block: HandBackBlock,
    pub notify_drained: NotifyDrained,
    pub notify_complete: NotifyComplete,
}

unsafe extern "C" fn missing_handle_release(_handle: *mut u8) {
    panic!("client-return-region operation called without implementation")
}
unsafe extern "C" fn missing_hand_back_block(_client: *mut u8, _block: *mut u32) {
    panic!("client-return-region operation called without implementation")
}
unsafe extern "C" fn missing_notify_drained(_client: *mut u8, _flag: u32) {
    panic!("client-return-region operation called without implementation")
}
unsafe extern "C" fn missing_notify_complete(_client: *mut u8) {
    panic!("client-return-region operation called without implementation")
}
pub const DEFAULT_CLIENT_RETURN_REGION_OPS: ClientReturnRegionOps = ClientReturnRegionOps {
    release_handle: missing_handle_release,
    hand_back_block: missing_hand_back_block,
    notify_drained: missing_notify_drained,
    notify_complete: missing_notify_complete,
};

pub static mut CLIENT_RETURN_REGION_OPS: ClientReturnRegionOps = DEFAULT_CLIENT_RETURN_REGION_OPS;

#[cfg(not(target_os = "none"))]
macro_rules! op {
    ($field:ident) => { unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CLIENT_RETURN_REGION_OPS.$field)) } };
}
macro_rules! mutex_op {
    ($field:ident) => { unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) } };
}
#[cfg(target_os = "none")]
unsafe fn release_handle(handle: *mut u8) {
    let release: HandleRelease = core::mem::transmute(RETAIL_HANDLE_RELEASE);
    release(handle);
}
#[cfg(not(target_os = "none"))]
unsafe fn release_handle(handle: *mut u8) { (op!(release_handle))(handle); }
#[cfg(target_os = "none")]
unsafe fn hand_back_block(client: *mut u8, block: *mut u32) {
    let hand_back: HandBackBlock = core::mem::transmute(RETAIL_HAND_BACK_BLOCK);
    hand_back(client, block);
}
#[cfg(not(target_os = "none"))]
unsafe fn hand_back_block(client: *mut u8, block: *mut u32) { (op!(hand_back_block))(client, block); }
#[cfg(target_os = "none")]
unsafe fn notify_drained(client: *mut u8) {
    let notify: NotifyDrained = core::mem::transmute(RETAIL_NOTIFY_DRAINED);
    notify(client, 1);
}
#[cfg(not(target_os = "none"))]
unsafe fn notify_drained(client: *mut u8) { (op!(notify_drained))(client, 1); }
#[cfg(target_os = "none")]
unsafe fn notify_complete(client: *mut u8) {
    let notify: NotifyComplete = core::mem::transmute(RETAIL_NOTIFY_COMPLETE);
    notify(client);
}
#[cfg(not(target_os = "none"))]
unsafe fn notify_complete(client: *mut u8) { (op!(notify_complete))(client); }

/// Returns one region from `returned` to `client`'s manager under its mutex.
/// `returned` must contain a readable cell pointer at target word 1 and that
/// cell must contain a readable block word at target word 3.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn client_return_region(client: *mut u8, returned: *mut u8) {
    (mutex_op!(lock))(client.add(CLIENT_MUTEX_OFFSET));
    let cell = (returned as *const usize).add(RETURNED_HANDLE_CELL_INDEX).read() as *const u32;
    let mut block = cell.add(CELL_BLOCK_INDEX).read();
    release_handle(returned);
    hand_back_block(client, core::ptr::addr_of_mut!(block));
    notify_drained(client);
    notify_complete(client);
    (mutex_op!(unlock))(client.add(CLIENT_MUTEX_OFFSET));
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::block_region::{RegionMutexOps, DEFAULT_REGION_MUTEX_OPS};
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u32; 6] = [0; 6];
    static mut EVENT_COUNT: usize = 0;
    static mut BLOCK: u32 = 0;
    fn event(value: u32) { unsafe { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; } }
    unsafe extern "C" fn lock(_mutex: *mut u8) -> u32 { event(1); 0 }
    unsafe extern "C" fn release(handle: *mut u8) { event(2); (*(handle as *mut usize).add(1) as *mut u32).add(3).write(0); }
    unsafe extern "C" fn hand_back(_client: *mut u8, block: *mut u32) { event(3); BLOCK = block.read(); }
    unsafe extern "C" fn drained(_client: *mut u8, flag: u32) { assert_eq!(flag, 1); event(4); }
    unsafe extern "C" fn complete(_client: *mut u8) { event(5); }
    unsafe extern "C" fn unlock(_mutex: *mut u8) -> u32 { event(6); 0 }
    struct Reset { _guard: MutexGuard<'static, ()>, ops: ClientReturnRegionOps, mutex: RegionMutexOps }
    impl Drop for Reset { fn drop(&mut self) { unsafe { addr_of_mut!(CLIENT_RETURN_REGION_OPS).write(self.ops); addr_of_mut!(REGION_MUTEX_OPS).write(self.mutex); } } }
    fn install() -> Reset { let guard = LOCK.lock(); unsafe { let reset = Reset { _guard: guard, ops: CLIENT_RETURN_REGION_OPS, mutex: REGION_MUTEX_OPS }; CLIENT_RETURN_REGION_OPS = ClientReturnRegionOps { release_handle: release, hand_back_block: hand_back, notify_drained: drained, notify_complete: complete }; REGION_MUTEX_OPS = RegionMutexOps { lock, unlock }; EVENT_COUNT = 0; BLOCK = 0; reset } }
    #[test]
    fn snapshots_block_before_releasing_handle_and_completes_protocol() {
        let _reset = install();
        let mut client = [0_u8; 0x28];
        let mut cell = [0_u32; 4]; cell[3] = 0xfeed_beef;
        let mut returned = [0_usize; 2]; returned[1] = cell.as_mut_ptr() as usize;
        unsafe { client_return_region(client.as_mut_ptr(), returned.as_mut_ptr().cast()); }
        unsafe { assert_eq!(BLOCK, 0xfeed_beef); assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2, 3, 4, 5, 6]); }
        assert_eq!(cell[3], 0, "release ran after the block snapshot");
    }
}
