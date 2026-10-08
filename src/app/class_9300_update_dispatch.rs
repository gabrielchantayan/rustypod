//! Mode-selected update dispatch for registry class 0x9300.

#[cfg(not(target_os = "none"))]
static mut HOST_REFRESH: Option<unsafe extern "C" fn(*mut u8)> = None;

/// Install the host substitute for the unported refresh helper at 0x0812fe68.
/// # Safety
/// Installation and calls must be externally serialized; the callback must
/// implement the retail helper's object contract.
#[cfg(not(target_os = "none"))]
pub unsafe fn set_host_refresh(refresh: Option<unsafe extern "C" fn(*mut u8)>) {
    core::ptr::addr_of_mut!(HOST_REFRESH).write(refresh);
}

/// Original `FUN_0812ff28` @ 0x0812ff28; true size 16 bytes, ending at
/// the independent push at 0x0812ff38. Whole-image aligned A32 decoding
/// verifies two inbound plain BLs and zero predicated BLs. The body has
/// no BL/BLX calls, only two conditional tail branches.
///
/// Mode zero calls the existing retail refresh helper at 0x0812fe68 with
/// the unchanged receiver. Every nonzero mode restarts the embedded timer
/// at byte offset +0x44 through the ported timer_restart at 0x0812bf4c.
/// Deliberate deviations: the unported refresh uses a fixed-address call
/// on target and an explicit host substitute; timer_restart retains its
/// existing dependency seams. Both verified callers discard r0, so the
/// inconsistent leftover return registers are represented as void.
/// # Safety
/// The receiver must satisfy the refresh helper's contract for mode zero,
/// or contain a valid timer at +0x44 otherwise. Host mode zero requires
/// an installed refresh substitute.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn class_9300_update_dispatch(this: *mut u8, mode: u32) {
    if mode == 0 {
        #[cfg(target_os = "none")]
        let refresh: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0812_fe68usize);
        #[cfg(not(target_os = "none"))]
        let refresh = core::ptr::addr_of!(HOST_REFRESH).read().expect("install class-0x9300 host refresh");
        refresh(this);
    } else {
        crate::drivers::timer::timer_restart(this.add(0x44));
    }
}
