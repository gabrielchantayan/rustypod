//! `font_descriptor_cached_resource` — original: `FUN_0829de34` @
//! `0x0829de34` (144 bytes, `0x0829de34..0x0829dec4`). The next independently
//! linked function begins at `0x0829dec4` with `mov r0,#0x2600; bx lr`.
//! Raw A32 branch decoding finds three direct inbound plain `bl` calls
//! (`0x0808dca0`, `0x0808dd30`, `0x08275354`) and no predicated forms. The
//! body contains three unconditional direct `bl` instructions.
//!
//! # Algorithm
//!
//! Return the cached word at +0x0c when it is nonzero, or when the descriptor
//! backing word at +0x04 is zero. Otherwise dispatch on byte +0x01: modes zero
//! and one construct a resource from words +0x04/+0x08 with their respective
//! selector; mode one also registers it. Mode two resolves an 8-byte font
//! handle from backing +2, the caller's low-halfword selector, and constant
//! 0x80, then caches its first word with bit zero cleared. Other mode values
//! leave the cache unchanged.
//!
//! # Deliberate deviations
//!
//! The three direct retail calls are represented by typed target-address calls
//! and host seams. Their concrete identities are not inferred beyond the
//! recovered argument roles. This preserves the target ABI and permits host
//! tests without fabricating their behavior.

#[cfg(not(target_os = "none"))]
use core::ptr;

/// Target-width descriptor layout observed by this routine.
#[repr(C)]
pub struct FontDescriptorCache {
    pub first_byte: u8,
    pub mode: u8,
    pub reserved: u16,
    pub backing: u32,
    pub backing_argument: u32,
    pub cached_resource: u32,
}

const _: () = assert!(core::mem::size_of::<FontDescriptorCache>() == 0x10);

pub type FontDescriptorResourceConstruct = unsafe extern "C" fn(u32, u32, u32) -> u32;
pub type FontDescriptorResourceRegister = unsafe extern "C" fn(u32);
pub type FontDescriptorFontHandle = unsafe extern "C" fn(*mut u32, *const u8, u32, u32);

#[cfg(target_os = "none")]
const RETAIL_FONT_DESCRIPTOR_RESOURCE_CONSTRUCT: usize = 0x0826_b318;
#[cfg(target_os = "none")]
const RETAIL_FONT_DESCRIPTOR_RESOURCE_REGISTER: usize = 0x0827_50b8;
#[cfg(target_os = "none")]
const RETAIL_FONT_DESCRIPTOR_FONT_HANDLE: usize = 0x0827_56fc;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_resource(backing: u32, backing_argument: u32, selector: u32) -> u32 {
    let construct: FontDescriptorResourceConstruct =
        core::mem::transmute(RETAIL_FONT_DESCRIPTOR_RESOURCE_CONSTRUCT);
    construct(backing, backing_argument, selector)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn register_resource(resource: u32) {
    let register: FontDescriptorResourceRegister =
        core::mem::transmute(RETAIL_FONT_DESCRIPTOR_RESOURCE_REGISTER);
    register(resource);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resolve_font_handle(out: *mut u32, name: *const u8, selector: u32, style: u32) {
    let resolve: FontDescriptorFontHandle =
        core::mem::transmute(RETAIL_FONT_DESCRIPTOR_FONT_HANDLE);
    resolve(out, name, selector, style);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct FontDescriptorCachedResourceOps {
    pub construct: FontDescriptorResourceConstruct,
    pub register: FontDescriptorResourceRegister,
    pub resolve_font_handle: FontDescriptorFontHandle,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct(_backing: u32, _backing_argument: u32, _selector: u32) -> u32 {
    panic!("FUN_0826b318 is unported; install FONT_DESCRIPTOR_CACHED_RESOURCE_OPS")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_register(_resource: u32) {
    panic!("FUN_082750b8 is unported; install FONT_DESCRIPTOR_CACHED_RESOURCE_OPS")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resolve_font_handle(
    _out: *mut u32,
    _name: *const u8,
    _selector: u32,
    _style: u32,
) {
    panic!("FUN_082756fc requires FONT_DESCRIPTOR_CACHED_RESOURCE_OPS")
}

#[cfg(not(target_os = "none"))]
pub static mut FONT_DESCRIPTOR_CACHED_RESOURCE_OPS: FontDescriptorCachedResourceOps =
    FontDescriptorCachedResourceOps {
        construct: missing_construct,
        register: missing_register,
        resolve_font_handle: missing_resolve_font_handle,
    };

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cached_resource_ops() -> FontDescriptorCachedResourceOps {
    ptr::read_volatile(ptr::addr_of!(FONT_DESCRIPTOR_CACHED_RESOURCE_OPS))
}

/// Resolve and cache the resource described by `descriptor`.
///
/// The descriptor must be readable and writable for 16 bytes at 4-byte
/// alignment. `variant` is narrowed to its low 16 bits only in mode two;
/// `scratch_first` and `scratch_second` supply the original stack words that
/// mode two passes as the font-handle output pair before the callee overwrites
/// them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn font_descriptor_cached_resource(
    descriptor: *mut FontDescriptorCache,
    variant: u16,
    scratch_first: u32,
    scratch_second: u32,
) -> u32 {
    let descriptor = &mut *descriptor;
    if descriptor.cached_resource != 0 || descriptor.backing == 0 {
        return descriptor.cached_resource;
    }

    let resource = match descriptor.mode {
        0 => {
            #[cfg(target_os = "none")]
            { construct_resource(descriptor.backing, descriptor.backing_argument, 0) }
            #[cfg(not(target_os = "none"))]
            { (cached_resource_ops().construct)(descriptor.backing, descriptor.backing_argument, 0) }
        }
        1 => {
            #[cfg(target_os = "none")]
            let resource = construct_resource(descriptor.backing, descriptor.backing_argument, 1);
            #[cfg(not(target_os = "none"))]
            let resource = (cached_resource_ops().construct)(descriptor.backing, descriptor.backing_argument, 1);
            #[cfg(target_os = "none")]
            register_resource(resource);
            #[cfg(not(target_os = "none"))]
            (cached_resource_ops().register)(resource);
            return { descriptor.cached_resource = resource; resource };
        }
        2 => {
            let mut handle = [scratch_first, scratch_second];
            #[cfg(target_os = "none")]
            resolve_font_handle(handle.as_mut_ptr(), (descriptor.backing as usize + 2) as *const u8, variant as u32, 0x80);
            #[cfg(not(target_os = "none"))]
            (cached_resource_ops().resolve_font_handle)(handle.as_mut_ptr(), (descriptor.backing as usize + 2) as *const u8, variant as u32, 0x80);
            handle[0] & !1
        }
        _ => return descriptor.cached_resource,
    };
    descriptor.cached_resource = resource;
    resource
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCT_ARGS: (u32, u32, u32) = (0, 0, 0);
    static mut REGISTERED: u32 = 0;
    static mut HANDLE_ARGS: (usize, u32, u32, u32, u32) = (0, 0, 0, 0, 0);

    unsafe extern "C" fn construct(backing: u32, argument: u32, selector: u32) -> u32 {
        CONSTRUCT_ARGS = (backing, argument, selector);
        0xfeed_cafe
    }
    unsafe extern "C" fn register(resource: u32) { REGISTERED = resource; }
    unsafe extern "C" fn resolve(out: *mut u32, name: *const u8, selector: u32, style: u32) {
        HANDLE_ARGS = (name as usize, selector, style, *out, *out.add(1));
        *out = 0x1234_5679;
        *out.add(1) = 0xdead_beef;
    }

    unsafe fn install_ops() {
        FONT_DESCRIPTOR_CACHED_RESOURCE_OPS = FontDescriptorCachedResourceOps {
            construct,
            register,
            resolve_font_handle: resolve,
        };
        CONSTRUCT_ARGS = (0, 0, 0);
        REGISTERED = 0;
        HANDLE_ARGS = (0, 0, 0, 0, 0);
    }

    #[test]
    fn cached_or_unbacked_descriptor_skips_every_callback() {
        let _guard = OPS_LOCK.lock();
        unsafe { install_ops(); }
        let mut cached = FontDescriptorCache { first_byte: 0, mode: 1, reserved: 0, backing: 4, backing_argument: 5, cached_resource: 9 };
        let mut unbacked = FontDescriptorCache { first_byte: 0, mode: 2, reserved: 0, backing: 0, backing_argument: 5, cached_resource: 0 };
        unsafe {
            assert_eq!(font_descriptor_cached_resource(&mut cached, 3, 7, 8), 9);
            assert_eq!(font_descriptor_cached_resource(&mut unbacked, 3, 7, 8), 0);
            assert_eq!(CONSTRUCT_ARGS, (0, 0, 0));
            assert_eq!(REGISTERED, 0);
            assert_eq!(HANDLE_ARGS, (0, 0, 0, 0, 0));
        }
    }

    #[test]
    fn construct_modes_cache_and_only_mode_one_registers() {
        let _guard = OPS_LOCK.lock();
        unsafe { install_ops(); }
        let mut descriptor = FontDescriptorCache { first_byte: 0, mode: 0, reserved: 0, backing: 0x1000, backing_argument: 0x2000, cached_resource: 0 };
        unsafe {
            assert_eq!(font_descriptor_cached_resource(&mut descriptor, 0xffff, 0, 0), 0xfeed_cafe);
            assert_eq!(CONSTRUCT_ARGS, (0x1000, 0x2000, 0));
            assert_eq!(REGISTERED, 0);
            descriptor.mode = 1;
            descriptor.cached_resource = 0;
            assert_eq!(font_descriptor_cached_resource(&mut descriptor, 0, 0, 0), 0xfeed_cafe);
            assert_eq!(CONSTRUCT_ARGS, (0x1000, 0x2000, 1));
            assert_eq!(REGISTERED, 0xfeed_cafe);
        }
    }

    #[test]
    fn font_handle_mode_masks_low_bit_and_forwards_stack_words() {
        let _guard = OPS_LOCK.lock();
        unsafe { install_ops(); }
        let mut descriptor = FontDescriptorCache { first_byte: 0, mode: 2, reserved: 0, backing: 0x1122_3344, backing_argument: 0, cached_resource: 0 };
        unsafe {
            assert_eq!(font_descriptor_cached_resource(&mut descriptor, 0xabcd, 0xaaaa_5555, 0x1357_2468), 0x1234_5678);
            assert_eq!(descriptor.cached_resource, 0x1234_5678);
            assert_eq!(HANDLE_ARGS, (0x1122_3346, 0xabcd, 0x80, 0xaaaa_5555, 0x1357_2468));
        }
    }
}
