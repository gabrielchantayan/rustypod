//! Raw mask-ROM task-unblock-range gateway wrapper.
//!
//! RTXC's `KS_unblock(start, end)` service unblocks every task in the inclusive
//! task-id range. The `0x08038250` veneer reaches its mask-ROM implementation
//! at `0x22004298`; the retailOS mirror below dispatches selector `0x1e` through
//! the shared foreign-ROM gateway binding.

use crate::heap::rom_task_start::gateway_dispatch;

/// Fully initialized three-word request frame for RTXC service 30.
pub type TaskUnblockRangeRequest = [u32; 3];

/// task_unblock_range_gateway — original: `FUN_08004298` @ `0x08004298` (28 bytes).
///
/// Reference: `decomp/c/000/08004298_FUN_08004298.c`; raw assembly at
/// `0x08004298`; direct veneer `0x08038250 -> 0x22004298`; and RTXCbug callers
/// at `0x082bf120`, `0x082bfa84`, and `0x08393cfc`. They pass `1, max_task_id`
/// to unblock every configured task or `task_id, task_id` for one task, which
/// identifies this as RTXC `KS_unblock(start, end)`. Builds the fully initialized
/// request `{ 0x1e, start_task_id, end_task_id }`, delegates it to
/// `FUN_08003660`, and deliberately discards every post-dispatch word: the
/// original pops its saved registers into `r2`, `r3`, and `ip`, then returns
/// `void`. The shared volatile gateway hook is the necessary foreign-ROM seam;
/// target integration must bind the real dispatcher rather than synthesize a
/// result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_unblock_range_gateway(start_task_id: u32, end_task_id: u32) {
    let mut request: TaskUnblockRangeRequest = [0x1e, start_task_id, end_task_id];
    gateway_dispatch()(request.as_mut_ptr());
}

/// task_unblock_range_entry — original: `thunk_EXT_FUN_22004298` @
/// `0x08038250` (8-byte literal veneer; 4 direct `bl` call sites: 3 plain,
/// 1 predicated).
///
/// Raw words establish the complete extent: `e51ff004` (`ldr pc, [pc, #-4]`)
/// at `0x08038250`, with target literal `0x22004298` at `0x08038254`.
/// The boot relocator mirrors the 28-byte [`task_unblock_range_gateway`] body
/// to that IRAM address. Direct ARM branch decoding finds plain `bl` callers
/// at `0x082bf1e4`, `0x082bfc18`, and `0x08394068`, plus predicated `blle` at
/// `0x0839408c`; none is a plain branch.
///
/// Deliberate deviation: Rust cannot encode the veneer’s literal load to
/// `pc`; this entry makes the established mirror-body behavior explicit. A
/// distinct target-only section keeps this separately hooked call target from
/// being folded with its body.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.task_unblock_range_entry")]
#[inline(never)]
pub unsafe extern "C" fn task_unblock_range_entry(start_task_id: u32, end_task_id: u32) {
    task_unblock_range_gateway(start_task_id, end_task_id)
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::rom_task_start::{
        RomGatewayOps, DEFAULT_ROM_GATEWAY_OPS, ROM_GATEWAY_OPS,
    };
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RECORDED_REQUEST: TaskUnblockRangeRequest = [0; 3];

    unsafe extern "C" fn record_and_clobber(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        addr_of_mut!(RECORDED_REQUEST).write([request.read(), request.add(1).read(), request.add(2).read()]);
        request.write(0xfeed_cafe);
        request.add(1).write(0x1234_5678);
        request.add(2).write(0xdead_beef);
    }

    #[test]
    fn entry_forwards_full_width_range_and_discards_gateway_output() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(RECORDED_REQUEST).write([0; 3]);
            addr_of_mut!(ROM_GATEWAY_OPS).write(RomGatewayOps {
                dispatch: record_and_clobber,
            });

            let (): () = task_unblock_range_entry(0, u32::MAX);

            assert_eq!(addr_of!(CALLS).read(), 1);
            assert_eq!(addr_of!(RECORDED_REQUEST).read(), [0x1e, 0, u32::MAX]);
            addr_of_mut!(ROM_GATEWAY_OPS).write(DEFAULT_ROM_GATEWAY_OPS);
        }
        drop(guard);
    }
}
