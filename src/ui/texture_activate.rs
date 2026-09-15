//! Texture activation — retailOS `FUN_08281140` @ 0x08281140.
//!
//! **84 bytes**, binary-verified from `push {r4-r6,lr}` at 0x08281140 through
//! `pop {r4-r6,pc}` at 0x08281188; the independently linked texture-upload
//! wrapper starts at 0x08281194. Aligned ARM B/BL-immediate decoding finds
//! **five plain `bl` inbound call sites** (0x08281048, 0x08281098,
//! 0x082810e4, 0x0828111c, and 0x082811a8), with no predicated inbound `bl`.
//! The body has one predicated `bleq` to `video_engine_enable_flag` and one
//! conditional tail branch to the unported `FUN_082d0ce0`.
//!
//! # Algorithm
//!
//! Lazily enables video-engine flag 0x0de1, then compares the texture's GL
//! name with the cached word at 0x089d00cc. A matching name is a no-op; a
//! changed name updates the cache and tail-dispatches flag 0x0de1 to the
//! unported video-engine wrapper at 0x082d0ce0.
//!
//! # Deliberate deviations
//!
//! The tail target has no verified semantic identity beyond its observed
//! video-engine behavior, so target builds call it by address. Host builds
//! replace the firmware cache and tail target with test seams.

#[cfg(not(target_arch = "arm"))]
use core::ptr::{addr_of, addr_of_mut};

use crate::ui::texture_upload::Texture;
use crate::util::video_engine::video_engine_enable_flag;

/// Firmware cache structure used by the original at 0x089d00c8.
#[cfg(target_arch = "arm")]
const TEXTURE_BINDING_CACHE_ADDR: usize = 0x089d_00c8;

#[cfg(not(target_arch = "arm"))]
static mut MOCK_INITIALIZED: u8 = 0;
#[cfg(not(target_arch = "arm"))]
static mut MOCK_GL_NAME: u32 = 0;

/// `FUN_082d0ce0`, the unported target of the original conditional tail branch.
type TextureBindingRefresh = unsafe extern "C" fn(u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_texture_binding_refresh(flag: u32) {
    let refresh: TextureBindingRefresh = unsafe { core::mem::transmute(0x082d_0ce0usize) };
    unsafe { refresh(flag) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_texture_binding_refresh(_flag: u32) {}

#[cfg(target_os = "none")]
static mut TEXTURE_BINDING_REFRESH: TextureBindingRefresh = firmware_texture_binding_refresh;
#[cfg(not(target_os = "none"))]
static mut TEXTURE_BINDING_REFRESH: TextureBindingRefresh = missing_texture_binding_refresh;

#[cfg(test)]
pub unsafe fn set_mock_texture_binding_refresh(refresh: TextureBindingRefresh) {
    unsafe { *addr_of_mut!(TEXTURE_BINDING_REFRESH) = refresh };
}

#[cfg(test)]
pub unsafe fn reset_mock_texture_binding_cache() {
    unsafe {
        *addr_of_mut!(MOCK_INITIALIZED) = 0;
        *addr_of_mut!(MOCK_GL_NAME) = 0;
        *addr_of_mut!(TEXTURE_BINDING_REFRESH) = missing_texture_binding_refresh;
    }
}

#[inline]
unsafe fn cache_initialized() -> u8 {
    #[cfg(target_arch = "arm")]
    unsafe {
        (TEXTURE_BINDING_CACHE_ADDR as *const u8).read_volatile()
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        *addr_of!(MOCK_INITIALIZED)
    }
}

#[inline]
unsafe fn set_cache_initialized() {
    #[cfg(target_arch = "arm")]
    unsafe {
        (TEXTURE_BINDING_CACHE_ADDR as *mut u8).write_volatile(1)
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        *addr_of_mut!(MOCK_INITIALIZED) = 1
    }
}

#[inline]
unsafe fn cached_gl_name() -> u32 {
    #[cfg(target_arch = "arm")]
    unsafe {
        ((TEXTURE_BINDING_CACHE_ADDR + 4) as *const u32).read_volatile()
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        *addr_of!(MOCK_GL_NAME)
    }
}

#[inline]
unsafe fn set_cached_gl_name(gl_name: u32) {
    #[cfg(target_arch = "arm")]
    unsafe {
        ((TEXTURE_BINDING_CACHE_ADDR + 4) as *mut u32).write_volatile(gl_name)
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        *addr_of_mut!(MOCK_GL_NAME) = gl_name
    }
}

/// texture_activate — retailOS `FUN_08281140` @ 0x08281140 (84 bytes).
///
/// # Safety
///
/// `texture` must point to a readable 12-byte [`Texture`]. The function has
/// no NULL check, matching the retail body.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn texture_activate(texture: *mut Texture) {
    unsafe {
        if cache_initialized() == 0 {
            set_cache_initialized();
            video_engine_enable_flag(0x0de1);
        }

        let gl_name = (*texture).gl_name;
        if gl_name == cached_gl_name() {
            return;
        }
        set_cached_gl_name(gl_name);
        let refresh = core::ptr::read_volatile(core::ptr::addr_of!(TEXTURE_BINDING_REFRESH));
        refresh(0x0de1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    use crate::ui::texture_upload::TEXTURE_UPLOAD_TEST_LOCK;

    static mut REFRESHED_FLAGS: [u32; 4] = [0; 4];
    static mut REFRESH_COUNT: usize = 0;

    unsafe extern "C" fn record_refresh(flag: u32) {
        unsafe {
            REFRESHED_FLAGS[REFRESH_COUNT] = flag;
            REFRESH_COUNT += 1;
        }
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { reset_mock_texture_binding_cache() };
        }
    }

    #[test]
    fn activates_only_for_changed_gl_names() {
        let _lock = TEXTURE_UPLOAD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _reset = Reset;
        let mut first = Texture {
            gl_name: 1,
            pixel_format: 0,
            reserved_5: 0,
            width: 0,
            height: 0,
            reserved_a: [0; 2],
        };
        let mut second = Texture { gl_name: u32::MAX, ..first };

        unsafe {
            REFRESHED_FLAGS = [0; 4];
            REFRESH_COUNT = 0;
            set_mock_texture_binding_refresh(record_refresh);
            texture_activate(&mut first);
            texture_activate(&mut first);
            texture_activate(&mut second);
        }

        unsafe {
            assert_eq!(REFRESH_COUNT, 2);
            assert_eq!(&REFRESHED_FLAGS[..REFRESH_COUNT], &[0x0de1, 0x0de1]);
        }
    }
}
