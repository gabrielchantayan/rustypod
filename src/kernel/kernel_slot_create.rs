//! Kernel slot creation wrapper.

use crate::kernel::task_lock::{kernel_create_dispatch, kernel_op_dispatch};

/// `kernel_slot_create` — retailOS load address `0x080a3cf0`, 64 bytes
/// (`0x080a3cf0..0x080a3d30`).
///
/// The unchecked slot word is the kernel-create selector. Zero returns
/// `EINVAL` (26); otherwise the create dispatcher runs first, then class-3
/// object setup runs only after a zero create status. Any dispatcher failure
/// returns `EBUSY` (20). The body has two unconditional internal `bl` calls,
/// no predicated `bl` calls, and three unconditional incoming `bl` sites.
///
/// Deliberate deviation: the ROM create wrapper at `0x22003e70` consumes only
/// r0, but the shared Rust seam takes two words. Its ignored second word is
/// supplied as zero instead of preserving the caller's incidental r1 value.
#[cfg_attr(target_os = "none", link_section = ".text.kernel_slot_create")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kernel_slot_create(slot: *mut usize) -> usize {
    let selector = slot.read();
    if selector == 0 {
        return 26;
    }
    if kernel_create_dispatch(selector, 0) != 0 {
        return 20;
    }
    if kernel_op_dispatch(3, slot as usize) != 0 {
        return 20;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::kernel_slot_create;
    use crate::kernel::task_lock::{RomThunkOps, ROM_KERNEL};
    use crate::kernel::task_lock::tests::OPS_LOCK;

    static mut CREATE_STATUS: usize = 0;
    static mut SETUP_STATUS: usize = 0;
    static mut CREATE_ARGS: [usize; 2] = [0; 2];
    static mut SETUP_ARGS: [usize; 2] = [0; 2];
    static mut CREATE_CALLS: usize = 0;
    static mut SETUP_CALLS: usize = 0;

    unsafe extern "C" fn create(selector: usize, ignored: usize) -> usize {
        CREATE_CALLS += 1;
        CREATE_ARGS = [selector, ignored];
        CREATE_STATUS
    }

    unsafe extern "C" fn setup(class: usize, slot: usize) -> usize {
        SETUP_CALLS += 1;
        SETUP_ARGS = [class, slot];
        SETUP_STATUS
    }

    fn install(create_status: usize, setup_status: usize) {
        unsafe {
            CREATE_STATUS = create_status;
            SETUP_STATUS = setup_status;
            CREATE_ARGS = [0; 2];
            SETUP_ARGS = [0; 2];
            CREATE_CALLS = 0;
            SETUP_CALLS = 0;
            let mut hooks: RomThunkOps = ROM_KERNEL;
            hooks.kernel_create_dispatch = create;
            hooks.kernel_op_dispatch = setup;
            ROM_KERNEL = hooks;
        }
    }

    #[test]
    fn zero_selector_returns_einval_without_dispatch() {
        let _lock = OPS_LOCK.lock().unwrap();
        install(0, 0);
        let mut slot = 0;
        assert_eq!(unsafe { kernel_slot_create(&mut slot) }, 26);
        unsafe {
            assert_eq!(CREATE_CALLS, 0);
            assert_eq!(SETUP_CALLS, 0);
        }
    }

    #[test]
    fn create_failure_returns_ebusy_without_setup() {
        let _lock = OPS_LOCK.lock().unwrap();
        install(7, 0);
        let mut slot = 0x4a;
        assert_eq!(unsafe { kernel_slot_create(&mut slot) }, 20);
        unsafe {
            assert_eq!(CREATE_CALLS, 1);
            assert_eq!(CREATE_ARGS, [0x4a, 0]);
            assert_eq!(SETUP_CALLS, 0);
        }
    }

    #[test]
    fn setup_status_controls_result_after_create() {
        let _lock = OPS_LOCK.lock().unwrap();
        install(0, 0);
        let mut slot = usize::MAX;
        assert_eq!(unsafe { kernel_slot_create(&mut slot) }, 0);
        unsafe {
            assert_eq!(CREATE_ARGS, [usize::MAX, 0]);
            assert_eq!(SETUP_CALLS, 1);
            assert_eq!(SETUP_ARGS, [3, &mut slot as *mut usize as usize]);
        }

        install(0, 1);
        assert_eq!(unsafe { kernel_slot_create(&mut slot) }, 20);
        unsafe {
            assert_eq!(CREATE_CALLS, 1);
            assert_eq!(SETUP_CALLS, 1);
        }
    }
}
