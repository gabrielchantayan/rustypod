//! `activity_media_player_cleanup` — original: `FUN_081f9248` @ **0x081f9248**
//! (**56 bytes**, `0x081f9248..0x081f9280`; the next separately linked entry
//! begins at `0x081f9280`).
//!
//! # Algorithm
//!
//! When `finish` is nonzero, obtains the global media-player interface and
//! invokes its unresolved vtable slot `+0xbc`, passing `activity` and the word
//! at `activity+0x8c`. It then clears the activity byte at `+0x88` and the six
//! words at the target pointer stored at `+0xb8`. There are **3 direct inbound
//! `bl` calls, all unconditional** (`0x08216d94`, `0x0821d528`, `0x0821fcb8`),
//! **0 predicated `bl` calls**, one outbound direct `bl`, one dynamic `blx`,
//! and one direct tail branch.
//!
//! # Deliberate deviations
//!
//! The host implementation exposes the firmware-owned media-player getter as
//! a seam. The ARM implementation retains the decoded instructions, including
//! the literal veneer tail branch to retail `FUN_081bb3d0`.

const ACTIVITY_FLAG_OFFSET: usize = 0x88;
const MEDIA_ARGUMENT_OFFSET: usize = 0x8c;
const CLEAR_WORDS_OFFSET: usize = 0xb8;
const MEDIA_FINISH_SLOT: usize = 0xbc / 4;

/// Media-player interface vtable as far as the `+0xbc` call is recovered.
#[repr(C)]
pub struct MediaPlayerFinishVtable {
    pub unresolved_000_b8: [usize; MEDIA_FINISH_SLOT],
    pub finish_activity: unsafe extern "C" fn(activity: *mut u8, argument: u32),
}

/// Media-player interface object as far as this cleanup decodes it.
#[repr(C)]
pub struct MediaPlayerFinishInterface {
    pub vtable: *const MediaPlayerFinishVtable,
}

/// Getter ABI for the global media-player interface.
pub type MediaPlayerFinishGetter = unsafe extern "C" fn() -> *mut MediaPlayerFinishInterface;

/// Host replacement for the firmware-owned media-player getter.
#[derive(Clone, Copy)]
pub struct ActivityMediaPlayerCleanupOps {
    pub get_interface: MediaPlayerFinishGetter,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_interface() -> *mut MediaPlayerFinishInterface {
    panic!("activity_media_player_cleanup requires a media-player interface fixture")
}

#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_ACTIVITY_MEDIA_PLAYER_CLEANUP_OPS: ActivityMediaPlayerCleanupOps =
    ActivityMediaPlayerCleanupOps { get_interface: missing_interface };

#[cfg(not(target_arch = "arm"))]
pub static mut ACTIVITY_MEDIA_PLAYER_CLEANUP_OPS: ActivityMediaPlayerCleanupOps =
    DEFAULT_ACTIVITY_MEDIA_PLAYER_CLEANUP_OPS;

/// Finalizes media-player activity state and clears its six-word timing block.
///
/// # Safety
///
/// `activity` must point to writable target-layout storage through `+0xbb`.
/// Its `+0xb8` field must contain a writable, four-byte-aligned target pointer
/// to six words. When `finish` is nonzero, the configured media-player getter
/// must return a non-NULL interface with a readable `+0xbc` vtable entry.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn activity_media_player_cleanup(activity: *mut u8, finish: u32) {
    if finish != 0 {
        let ops = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(ACTIVITY_MEDIA_PLAYER_CLEANUP_OPS))
        };
        let interface = unsafe { (ops.get_interface)() };
        let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*interface).vtable)) };
        let argument = unsafe { core::ptr::read_unaligned(activity.add(MEDIA_ARGUMENT_OFFSET).cast::<u32>()) };
        unsafe { ((*vtable).finish_activity)(activity, argument) };
    }

    unsafe { activity.add(ACTIVITY_FLAG_OFFSET).write(0) };
    let clear_words = unsafe {
        core::ptr::read_unaligned(activity.add(CLEAR_WORDS_OFFSET).cast::<u32>()) as usize as *mut u32
    };
    for index in 0..6 {
        unsafe { clear_words.add(index).write(0) };
    }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl activity_media_player_cleanup
    .type activity_media_player_cleanup, %function
activity_media_player_cleanup:
    push    {{r4, lr}}
    cmp     r1, #0
    mov     r4, r0
    beq     1f
    bl      media_player_interface_get
    ldr     r2, [r0]
    ldr     r1, [r4, #0x8c]
    ldr     r2, [r2, #0xbc]
    blx     r2
1:
    mov     r0, #0
    strb    r0, [r4, #0x88]
    ldr     r0, [r4, #0xb8]
    pop     {{r4, lr}}
    b       retail_tick_accumulator_reset_timing_state
    .size activity_media_player_cleanup, . - activity_media_player_cleanup

retail_tick_accumulator_reset_timing_state:
    ldr     pc, [pc, #-4]
    .word   0x081bb3d0
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut GETTER_CALLS: u32 = 0;
    static mut FINISH_CALLS: u32 = 0;
    static mut SEEN_ACTIVITY: *mut u8 = core::ptr::null_mut();
    static mut SEEN_ARGUMENT: u32 = 0;
    static mut INTERFACE: MediaPlayerFinishInterface = MediaPlayerFinishInterface { vtable: core::ptr::null() };

    unsafe extern "C" fn record_finish(activity: *mut u8, argument: u32) {
        unsafe {
            FINISH_CALLS += 1;
            SEEN_ACTIVITY = activity;
            SEEN_ARGUMENT = argument;
        }
    }

    static VTABLE: MediaPlayerFinishVtable = MediaPlayerFinishVtable {
        unresolved_000_b8: [0; MEDIA_FINISH_SLOT],
        finish_activity: record_finish,
    };

    unsafe extern "C" fn record_get_interface() -> *mut MediaPlayerFinishInterface {
        unsafe {
            GETTER_CALLS += 1;
            addr_of_mut!(INTERFACE)
        }
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(GETTER_CALLS).write(0);
            addr_of_mut!(FINISH_CALLS).write(0);
            addr_of_mut!(SEEN_ACTIVITY).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_ARGUMENT).write(0);
            addr_of_mut!(INTERFACE).write(MediaPlayerFinishInterface { vtable: &VTABLE });
            addr_of_mut!(ACTIVITY_MEDIA_PLAYER_CLEANUP_OPS).write(ActivityMediaPlayerCleanupOps {
                get_interface: record_get_interface,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(ACTIVITY_MEDIA_PLAYER_CLEANUP_OPS)
                .write(DEFAULT_ACTIVITY_MEDIA_PLAYER_CLEANUP_OPS);
        }
        drop(guard);
    }

    #[test]
    fn conditionally_dispatches_then_clears_activity_and_target_words() {
        let Some(clear_words) = try_map_u32_slab(hints::ACTIVITY_MEDIA_PLAYER_CLEANUP, 24) else {
            return;
        };
        let guard = install_recorder();
        let mut activity = [0xa5u8; 0xbc];
        unsafe {
            let clear_words = clear_words.cast::<u32>();
            for index in 0..6 {
                clear_words.add(index).write(0x1111_0000 + index as u32);
            }
            activity[ACTIVITY_FLAG_OFFSET] = 1;
            activity.as_mut_ptr().add(MEDIA_ARGUMENT_OFFSET).cast::<u32>().write_unaligned(0x1234_5678);
            activity.as_mut_ptr().add(CLEAR_WORDS_OFFSET).cast::<u32>().write_unaligned(clear_words as usize as u32);

            activity_media_player_cleanup(activity.as_mut_ptr(), 0);
            assert_eq!(addr_of!(GETTER_CALLS).read(), 0);
            assert_eq!(addr_of!(FINISH_CALLS).read(), 0);
            assert_eq!(activity[ACTIVITY_FLAG_OFFSET], 0);
            assert_eq!([clear_words.read(), clear_words.add(1).read(), clear_words.add(2).read(), clear_words.add(3).read(), clear_words.add(4).read(), clear_words.add(5).read()], [0; 6]);

            for index in 0..6 {
                clear_words.add(index).write(0x1111_0000 + index as u32);
            }
            activity[ACTIVITY_FLAG_OFFSET] = 1;
            activity_media_player_cleanup(activity.as_mut_ptr(), 1);
            assert_eq!(addr_of!(GETTER_CALLS).read(), 1);
            assert_eq!(addr_of!(FINISH_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_ACTIVITY).read(), activity.as_mut_ptr());
            assert_eq!(addr_of!(SEEN_ARGUMENT).read(), 0x1234_5678);
            assert_eq!(activity[ACTIVITY_FLAG_OFFSET], 0);
            assert_eq!([clear_words.read(), clear_words.add(1).read(), clear_words.add(2).read(), clear_words.add(3).read(), clear_words.add(4).read(), clear_words.add(5).read()], [0; 6]);
        }
        restore_default(guard);
    }
}
