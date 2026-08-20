//! FreeType module lookup interfaces.
//!
//! `FT_Get_Module_Interface` is deliberately separate from the module-table
//! search at 0x0804c500. The retail function calls that still-unported lookup
//! and then reads the returned module's class interface pointer.

use core::ffi::c_void;

use crate::ft::stream::FtLibrary;

/// `FT_Module_Class` fields through `module_interface`.
///
/// On the retail 32-bit ABI, `module_interface` is at +0x14: flags and size
/// occupy the first two words, followed by `module_name`, `module_version`,
/// and `module_requires`.
#[repr(C)]
pub struct FtModuleClass {
    pub module_flags: u32,
    pub module_size: i32,
    pub module_name: *const u8,
    pub module_version: i32,
    pub module_requires: i32,
    pub module_interface: *const c_void,
}

/// `FT_ModuleRec` prefix. The class pointer is its first field on ARM.
#[repr(C)]
pub struct FtModule {
    pub clazz: *const FtModuleClass,
}

type FtGetModule = unsafe extern "C" fn(*mut FtLibrary, *const u8) -> *mut FtModule;

/// Uses the original `FT_Get_Module` while only this interface wrapper is
/// hooked. Its address is a load address in the resident retailOS image, not
/// a Rust port or a second implementation of 0x0804c500.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn ft_get_module(library: *mut FtLibrary, module_name: *const u8) -> *mut FtModule {
    let module: *mut FtModule;
    core::arch::asm!(
        "ldr r12, =0x0804c500",
        "blx r12",
        inlateout("r0") library => module,
        in("r1") module_name,
        clobber_abi("C"),
    );
    module
}

/// Host builds have no resident retailOS lookup routine. Tests install a
/// lookup seam, while an unconfigured host call has the same null result as a
/// failed stock lookup.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn ft_get_module_unavailable(
    _library: *mut FtLibrary,
    _module_name: *const u8,
) -> *mut FtModule {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
static mut FT_GET_MODULE: FtGetModule = ft_get_module_unavailable;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn ft_get_module(library: *mut FtLibrary, module_name: *const u8) -> *mut FtModule {
    core::ptr::read_volatile(core::ptr::addr_of!(FT_GET_MODULE))(library, module_name)
}

/// FreeType 2.3 `FT_Get_Module_Interface` (ftobjs.c) — original:
/// `FUN_0804c560` @ 0x0804c560 (24 bytes).
///
/// Delegates the library/module-name lookup to the resident `FT_Get_Module`
/// at 0x0804c500. A failed lookup returns NULL; otherwise this performs the
/// same nested `module->clazz->module_interface` read as the ARM `ldrne` pair
/// (+0x00 then +0x14). No deviations.
///
/// # Safety
/// `library` and `module_name` are passed unchanged to `FT_Get_Module`. If
/// that lookup returns non-NULL, it must designate a valid `FtModule` whose
/// class pointer designates a valid `FtModuleClass`, as the original requires.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_get_module_interface(
    library: *mut FtLibrary,
    module_name: *const u8,
) -> *const c_void {
    let module = ft_get_module(library, module_name);
    if module.is_null() {
        return core::ptr::null();
    }
    (*(*module).clazz).module_interface
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut, null, null_mut};

    static mut LOOKUP_LIBRARY: *mut FtLibrary = null_mut();
    static mut LOOKUP_NAME: *const u8 = null();
    static mut MODULE: FtModule = FtModule { clazz: null() };
    static mut CLASS: FtModuleClass = FtModuleClass {
        module_flags: 0,
        module_size: 0,
        module_name: null(),
        module_version: 0,
        module_requires: 0,
        module_interface: null(),
    };

    unsafe extern "C" fn lookup_returns_null(
        library: *mut FtLibrary,
        module_name: *const u8,
    ) -> *mut FtModule {
        LOOKUP_LIBRARY = library;
        LOOKUP_NAME = module_name;
        null_mut()
    }

    unsafe extern "C" fn lookup_returns_module(
        library: *mut FtLibrary,
        module_name: *const u8,
    ) -> *mut FtModule {
        LOOKUP_LIBRARY = library;
        LOOKUP_NAME = module_name;
        addr_of_mut!(MODULE)
    }

    unsafe fn install_lookup(lookup: FtGetModule) -> FtGetModule {
        let prior = core::ptr::read_volatile(addr_of!(FT_GET_MODULE));
        core::ptr::write_volatile(addr_of_mut!(FT_GET_MODULE), lookup);
        prior
    }

    #[test]
    fn module_interface_returns_null_when_module_lookup_fails() {
        unsafe {
            let prior = install_lookup(lookup_returns_null);
            let mut library = FtLibrary { memory: null_mut() };
            let name = b"missing\0";
            assert!(ft_get_module_interface(&mut library, name.as_ptr()).is_null());
            assert_eq!(LOOKUP_LIBRARY, &mut library as *mut FtLibrary);
            assert_eq!(LOOKUP_NAME, name.as_ptr());
            install_lookup(prior);
        }
    }

    #[test]
    fn module_interface_reads_the_returned_modules_class_interface() {
        unsafe {
            let prior = install_lookup(lookup_returns_module);
            let interface = 0x1234usize as *const c_void;
            CLASS.module_interface = interface;
            MODULE.clazz = addr_of!(CLASS);
            let mut library = FtLibrary { memory: null_mut() };
            let name = b"truetype\0";
            assert_eq!(ft_get_module_interface(&mut library, name.as_ptr()), interface);
            assert_eq!(LOOKUP_LIBRARY, &mut library as *mut FtLibrary);
            assert_eq!(LOOKUP_NAME, name.as_ptr());
            install_lookup(prior);
        }
    }
}
