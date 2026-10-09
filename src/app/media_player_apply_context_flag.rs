//! Forward the context's normalized flag to the media-player virtual interface.

use core::ptr;

type PlayerGet = unsafe extern "C" fn() -> *mut u8;
type ApplyFlag = unsafe extern "C" fn(*mut u8, u32) -> u32;

/// Prefix through the context pointer at target offset +0xf00. Native host
/// pointers occupy their natural width; the preceding words remain four bytes.
#[repr(C)]
pub struct MediaFlagOwner {
    pub preceding_words: [u32; 0xf00 / 4],
    pub context: *const u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_player_get() -> *mut u8 {
    panic!("install context flag player getter")
}
#[cfg(not(target_os = "none"))]
static mut HOST_PLAYER_GET: PlayerGet = missing_player_get;

/// Install the native-host singleton operation.
/// # Safety
/// Installation and calls must be externally serialized; the getter must
/// return an object with a valid native-pointer vtable containing slot 48.
#[cfg(not(target_os = "none"))]
pub unsafe fn set_host_player_get(get: PlayerGet) {
    ptr::addr_of_mut!(HOST_PLAYER_GET).write(get);
}

/// Original `FUN_080beaf8` @ 0x080beaf8; true size 44 bytes, ending at
/// the independent push prologue at 0x080beb24. Raw words verify one plain
/// outgoing BL (media_player_get), zero predicated BLs, and one BX virtual
/// tail dispatch. Whole-image scanning verifies two incoming plain BLs and
/// zero incoming predicated BLs.
///
/// Fetch the media-player singleton, load the owner's context at +0xf00,
/// read its unsigned flag byte at +0xb1a, and invoke player vtable slot
/// +0xc0 with 0 for zero or 1 for any nonzero byte. No NULL guards exist.
/// The virtual method's identity and flag meaning are not assumed.
///
/// Deliberate deviations: hosts install a singleton getter and use native
/// pointers with target word-indexed vtable slots. Return the virtual call's
/// r0 unchanged (opaque u32), preserving the raw tail-call behavior despite
/// Ghidra's void signature. Rust need not emit a tail call.
/// # Safety
/// Owner, context through +0xb1a, player, and vtable slot 48 must be valid.
/// The virtual method must obey the declared ARM ABI; host operations must
/// be installed and externally serialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_apply_context_flag(owner: *const MediaFlagOwner) -> u32 {
    #[cfg(target_os = "none")]
    let player = crate::app::singletons::media_player_get();
    #[cfg(not(target_os = "none"))]
    let player = ptr::addr_of!(HOST_PLAYER_GET).read()();
    let context = ptr::addr_of!((*owner).context).read();
    let vtable = player.cast::<*const usize>().read();
    let flag = context.add(0xb1a).read();
    let apply: ApplyFlag = core::mem::transmute(vtable.add(0xc0 / 4).read());
    apply(player, u32::from(flag != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut PLAYER: *mut Player = ptr::null_mut();
    #[repr(C)]
    struct Player { vtable: *const usize, enabled: u32 }
    unsafe extern "C" fn get_player() -> *mut u8 { PLAYER.cast() }
    unsafe extern "C" fn apply(player: *mut u8, flag: u32) -> u32 {
        let player = &mut *player.cast::<Player>();
        let previous = player.enabled;
        player.enabled = flag;
        previous
    }

    #[test]
    fn all_byte_values_normalize_and_zero_clears_previous_state() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = ptr::addr_of!(HOST_PLAYER_GET).read();
            let mut table = [0usize; 49];
            table[48] = apply as ApplyFlag as usize;
            let mut player = Player { vtable: table.as_ptr(), enabled: 7 };
            PLAYER = &mut player;
            set_host_player_get(get_player);
            let mut context = [0xa5u8; 0xb1b];
            let owner = MediaFlagOwner { preceding_words: [0; 0xf00 / 4], context: context.as_ptr() };
            for byte in 0..=255u8 {
                context[0xb1a] = byte;
                let previous = player.enabled;
                assert_eq!(media_player_apply_context_flag(&owner), previous);
                assert_eq!(player.enabled, if byte == 0 { 0 } else { 1 });
            }
            context[0xb1a] = 0;
            assert_eq!(media_player_apply_context_flag(&owner), 1);
            assert_eq!(player.enabled, 0);
            assert_eq!(context[0xb19], 0xa5);
            set_host_player_get(saved);
            PLAYER = ptr::null_mut();
        }
    }
}
