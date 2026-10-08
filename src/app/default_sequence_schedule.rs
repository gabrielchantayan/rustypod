//! Schedules default-sequence playback or handles its timer expiration.
//!
//! FUN_08109d80 @ 0x08109d80: true extent 52 bytes [0x08109d80,
//! 0x08109db4), comprising 48 code bytes and a 10,000-ms literal.
//! Full-image aligned A32 scan: zero plain inbound BLs, two BLEQs
//! (0x08109fdc, 0x0810a910). Outbound: one plain BL, zero predicated
//! BLs, one BNE to 0x081a2ba8 and one B to timer_restart.
//! Zero mode stops/reprograms the embedded timer at +0x18 to 10 seconds,
//! then restarts it. Any nonzero mode plays the manager's default sequence.
//! Raw 0x081a2ba8 initializes via 0x081a2998 and tail-calls 0x0826c884.
//! Deviations: return-position Rust calls represent tail branches; the
//! unported playback wrapper uses a verified retail address and host seam.
//! The manager pointer widens on hosts; its preceding 50 words do not.

use crate::drivers::timer::{timer_start_after, timer_restart};

#[repr(C)]
pub struct DefaultSequenceOwner {
    pub words: [u32; 50],
    pub manager: *mut u8,
}

type PlayDefault = unsafe extern "C" fn(*mut u8);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_play_default(_: *mut u8) {
    panic!("install default sequence playback host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut DEFAULT_SEQUENCE_PLAY: PlayDefault = missing_play_default;

/// # Safety
/// `owner` must be live and aligned. Zero mode requires a constructed timer
/// at +0x18; nonzero mode requires a manager accepted by retail 0x081a2ba8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn default_sequence_schedule(owner: *mut DefaultSequenceOwner, expired: u32) {
    if expired != 0 {
        #[cfg(target_os = "none")]
        let play: PlayDefault = core::mem::transmute(0x081a_2ba8usize);
        #[cfg(not(target_os = "none"))]
        let play = core::ptr::addr_of!(DEFAULT_SEQUENCE_PLAY).read();
        play((*owner).manager);
    } else {
        let timer = owner.cast::<u8>().add(0x18);
        timer_start_after(timer, 10_000);
        timer_restart(timer);
    }
}
