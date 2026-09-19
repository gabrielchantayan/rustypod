//! Display refresh transaction.

use crate::drivers::pwrcon::pwrcon_acquire_clock_2;

const DISPLAY_TRANSACTION_STATE: *mut u32 = 0x3830_0000 as *mut u32;
const DISPLAY_SERVICE_POINTER: *const u32 = 0x089c_a45c as *const u32;
const DISPLAY_BUSY_WORD: usize = 0x8c / core::mem::size_of::<u32>();
const DISPLAY_REFRESHING_WORD: usize = 0x80 / core::mem::size_of::<u32>();
const DISPLAY_PRESENT_SLOT: usize = 0x0c / core::mem::size_of::<u32>();

type DisplayPresent = unsafe extern "C" fn(u32, u32, u32, u32, u32);

#[cfg(target_os = "none")]
unsafe fn wait_for_display_idle() {
    while unsafe { core::ptr::read_volatile(DISPLAY_TRANSACTION_STATE.add(DISPLAY_BUSY_WORD)) } & 3 != 0 {}
}

#[cfg(target_os = "none")]
unsafe fn present_display() {
    let display_service = unsafe { core::ptr::read(DISPLAY_SERVICE_POINTER) } as *const u32;
    let vtable = unsafe { core::ptr::read(display_service) } as *const u32;
    let present: DisplayPresent = unsafe { core::mem::transmute(core::ptr::read(vtable.add(DISPLAY_PRESENT_SLOT))) };
    unsafe { present(0, 0, 0, 320, 240) };
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostDisplayOps {
    read_busy: unsafe extern "C" fn() -> u32,
    acquire_clock: unsafe extern "C" fn(),
    write_refreshing: unsafe extern "C" fn(u32),
    present: DisplayPresent,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_seam_uninstalled() -> u32 {
    panic!("install display-refresh host operations before calling display_refresh")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_acquire_clock_seam_uninstalled() {
    panic!("install display-refresh host operations before calling display_refresh")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_write_seam_uninstalled(_: u32) {
    panic!("install display-refresh host operations before calling display_refresh")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_present_seam_uninstalled(_: u32, _: u32, _: u32, _: u32, _: u32) {
    panic!("install display-refresh host operations before calling display_refresh")
}

#[cfg(not(target_os = "none"))]
static mut HOST_DISPLAY_OPS: HostDisplayOps = HostDisplayOps {
    read_busy: host_seam_uninstalled,
    acquire_clock: host_acquire_clock_seam_uninstalled,
    write_refreshing: host_write_seam_uninstalled,
    present: host_present_seam_uninstalled,
};

/// display_refresh — original entry: `FUN_080911c4` @ `0x080911c4`.
///
/// The assigned entry is an **8-byte wrapper** (`mov r0, #1; b 0x080af6b8`);
/// its next real function begins at `0x080911cc`. The shared body at
/// `0x080af6b8..0x080af734` is 124 bytes. Raw words find two unconditional
/// `bl` calls (`0x080af6c8`, `0x080af6e0`), one predicated `blne`
/// (`0x080af720`), and one indirect `blx` (`0x080af710`).
///
/// Waits for the display transaction's low two busy bits to clear, acquires
/// clock 2, marks refresh in progress, invokes vtable slot 3 with the full
/// 320x240 rectangle, clears the mark, then waits again because this entry
/// supplies a nonzero first argument. The vtable target has no established
/// name, so this port preserves it as indirect dispatch rather than inventing
/// a callee identity. Host builds deliberately replace only the raw global
/// state and indirect dispatch boundaries with a recording seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn display_refresh() -> u32 {
    #[cfg(target_os = "none")]
    unsafe {
        wait_for_display_idle();
        pwrcon_acquire_clock_2();
        core::ptr::write(DISPLAY_TRANSACTION_STATE.add(DISPLAY_REFRESHING_WORD), 1);
        present_display();
        core::ptr::write(DISPLAY_TRANSACTION_STATE.add(DISPLAY_REFRESHING_WORD), 0);
        wait_for_display_idle();
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(HOST_DISPLAY_OPS));
        while (ops.read_busy)() & 3 != 0 {}
        (ops.acquire_clock)();
        (ops.write_refreshing)(1);
        (ops.present)(0, 0, 0, 320, 240);
        (ops.write_refreshing)(0);
        while (ops.read_busy)() & 3 != 0 {}
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static BUSY_READS: AtomicU32 = AtomicU32::new(0);
    static REFRESHING: Mutex<std::vec::Vec<u32>> = Mutex::new(std::vec::Vec::new());
    static PRESENT: Mutex<std::vec::Vec<u32>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn read_busy() -> u32 {
        let reads = BUSY_READS.fetch_add(1, Ordering::SeqCst);
        if reads == 0 { 3 } else { 0 }
    }

    unsafe extern "C" fn acquire_clock() {}

    unsafe extern "C" fn write_refreshing(value: u32) {
        REFRESHING.lock().push(value);
    }

    unsafe extern "C" fn present(a: u32, b: u32, c: u32, width: u32, height: u32) {
        PRESENT.lock().extend_from_slice(&[a, b, c, width, height]);
    }

    unsafe fn install() {
        BUSY_READS.store(0, Ordering::SeqCst);
        REFRESHING.lock().clear();
        PRESENT.lock().clear();
        HOST_DISPLAY_OPS = HostDisplayOps { read_busy, acquire_clock, write_refreshing, present };
    }

    #[test]
    fn refresh_waits_marks_and_presents_the_full_screen() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            install();
            assert_eq!(display_refresh(), 0);
        }
        assert_eq!(*REFRESHING.lock(), [1, 0]);
        assert_eq!(*PRESENT.lock(), [0, 0, 0, 320, 240]);
        assert!(BUSY_READS.load(Ordering::SeqCst) >= 3);
    }
}
