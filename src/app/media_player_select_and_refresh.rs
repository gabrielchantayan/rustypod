//! Select and refresh a media player — `FUN_08112d5c` @ `0x08112d5c`.
//! True extent: [0x08112d5c, 0x08112d94), 56 bytes. Raw A32 decoding
//! finds two inbound plain BLs (0x08115848, 0x08115870), no predicated
//! inbound BLs; three outgoing plain BLs and no predicated outgoing BLs.
//! Pass player and selector to 0x0811169c. If it returns nonzero, refresh
//! through 0x081134a8, then call 0x08112b9c and return one iff its status
//! is zero. Otherwise return zero. Preserve player across all calls.
//! No target behavioral deviations. Unported callees retain verified raw
//! addresses and ABIs, not invented identities; host callbacks replace them.
//! Ghidra omits selector and incorrectly declares the final helper void.

type SelectCall = unsafe extern "C" fn(*mut u8, u32) -> u32;
type RefreshCall = unsafe extern "C" fn(*mut u8);
type StatusCall = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_select(_: *mut u8, _: u32) -> u32 { panic!("retail 0x0811169c unavailable on host") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh(_: *mut u8) { panic!("retail 0x081134a8 unavailable on host") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_status(_: *mut u8) -> u32 { panic!("retail 0x08112b9c unavailable on host") }

// Host callers must serialize replacement and restore these callbacks.
#[cfg(not(target_os = "none"))]
pub static mut SELECT_AT_0811169C: SelectCall = missing_select;
#[cfg(not(target_os = "none"))]
pub static mut REFRESH_AT_081134A8: RefreshCall = missing_refresh;
#[cfg(not(target_os = "none"))]
pub static mut STATUS_AT_08112B9C: StatusCall = missing_status;

/// # Safety
/// Player must be a complete live retail player accepted by all three helpers.
/// Host execution requires installed callbacks. No NULL validation is added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_select_and_refresh(player: *mut u8, selector: u32) -> u32 {
    #[cfg(target_os = "none")]
    let (select, refresh, status): (SelectCall, RefreshCall, StatusCall) = (
        core::mem::transmute(0x0811_169cusize),
        core::mem::transmute(0x0811_34a8usize),
        core::mem::transmute(0x0811_2b9cusize),
    );
    #[cfg(not(target_os = "none"))]
    let select = core::ptr::read_volatile(core::ptr::addr_of!(SELECT_AT_0811169C));
    if select(player, selector) == 0 { return 0; }
    #[cfg(not(target_os = "none"))]
    let refresh = core::ptr::read_volatile(core::ptr::addr_of!(REFRESH_AT_081134A8));
    refresh(player);
    #[cfg(not(target_os = "none"))]
    let status = core::ptr::read_volatile(core::ptr::addr_of!(STATUS_AT_08112B9C));
    u32::from(status(player) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Player { gate: u32, status: u32, selector: u32, phase: u32 }

    unsafe extern "C" fn select(player: *mut u8, selector: u32) -> u32 {
        let player = &mut *player.cast::<Player>();
        assert_eq!(player.phase, 0);
        player.selector = selector;
        player.phase = 1;
        player.gate
    }
    unsafe extern "C" fn refresh(player: *mut u8) {
        let player = &mut *player.cast::<Player>();
        assert_eq!(player.phase, 1);
        player.phase = 2;
    }
    unsafe extern "C" fn status(player: *mut u8) -> u32 {
        let player = &mut *player.cast::<Player>();
        assert_eq!(player.phase, 2);
        player.phase = 3;
        player.status
    }

    #[test]
    fn rejection_short_circuits_and_only_zero_status_succeeds() {
        unsafe {
            SELECT_AT_0811169C = select;
            REFRESH_AT_081134A8 = refresh;
            STATUS_AT_08112B9C = status;
            for gate in [0, 1, 0x8000_0000, u32::MAX] {
                for final_status in [0, 1, 0x8000_0000, u32::MAX] {
                    for selector in [0, 1, 0x8000_0000, u32::MAX] {
                        let mut player = Player { gate, status: final_status, selector: 7, phase: 0 };
                        let result = media_player_select_and_refresh((&mut player as *mut Player).cast(), selector);
                        assert_eq!(result, u32::from(gate != 0 && final_status == 0));
                        assert_eq!(player.phase, if gate == 0 { 1 } else { 3 });
                        assert_eq!(player.selector, selector);
                    }
                }
            }
            SELECT_AT_0811169C = missing_select;
            REFRESH_AT_081134A8 = missing_refresh;
            STATUS_AT_08112B9C = missing_status;
        }
    }
}
