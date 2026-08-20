//! FreeType module lookup interfaces.
//!
//! The module-table search at 0x0804c500 underlies
//! `FT_Get_Module_Interface` at 0x0804c560.

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

/// `FT_LibraryRec` fields used by `FT_Get_Module`.
///
/// The retail ARM record has `num_modules` at +0x18 and its 32-entry module
/// table at +0x1c. `FtLibrary` intentionally exposes only its shared prefix,
/// so this private view preserves the remainder needed by this one API.
#[repr(C)]
struct FtLibraryModuleTable {
    _memory: *mut c_void,
    _generic_data: *mut c_void,
    _generic_finalizer: *const c_void,
    _version_major: i32,
    _version_minor: i32,
    _version_patch: i32,
    num_modules: u32,
    modules: [*mut FtModule; 32],
}

/// FreeType 2.3 `FT_Get_Module` (`src/base/ftobjs.c`) — retailOS
/// `FUN_0804c500` at load address 0x0804c500, 96 bytes.
///
/// Returns null for a null library or module name. Otherwise it traverses
/// exactly `library->num_modules` entries from `library->modules`, comparing
/// each `module->clazz->module_name` NUL-terminated byte string to
/// `module_name`, and returns the first equal module. This is the direct
/// port of `/home/gabe/Programming/ipod-decomp/decomp/c/003/0804c500_FUN_0804c500.c`;
/// the ARM calls the resident `strcmp` at 0x08391e38 for each comparison.
///
/// # Safety
/// `library` must point to a valid retail `FT_LibraryRec` with at least
/// `num_modules` initialized table entries. Each examined module, its class,
/// and both name strings must be valid; the names must be NUL-terminated.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_get_module(
    library: *mut FtLibrary,
    module_name: *const u8,
) -> *mut FtModule {
    if library.is_null() || module_name.is_null() {
        return core::ptr::null_mut();
    }

    let library_record = &*library.cast::<FtLibraryModuleTable>();

    #[cfg(target_os = "none")]
    {
        let mut current = library_record.modules.as_ptr();
        let limit = current.add(library_record.num_modules as usize);

        while current < limit {
            let module = core::ptr::read_volatile(current);
            let mut comparison = (*(*module).clazz).module_name as usize;
            core::arch::asm!(
                "ldr r12, =0x08391e38",
                "blx r12",
                inlateout("r0") comparison,
                in("r1") module_name,
                clobber_abi("C"),
            );
            if comparison == 0 {
                return module;
            }
            current = current.add(1);
        }
    }

    #[cfg(not(target_os = "none"))]
    for index in 0..library_record.num_modules as usize {
        let module = core::ptr::read_volatile(library_record.modules.as_ptr().add(index));
        let mut candidate = (*(*module).clazz).module_name;
        let mut requested = module_name;

        loop {
            let candidate_byte = core::ptr::read_volatile(candidate);
            let requested_byte = core::ptr::read_volatile(requested);
            if candidate_byte != requested_byte {
                break;
            }
            if candidate_byte == 0 {
                return module;
            }
            candidate = candidate.add(1);
            requested = requested.add(1);
        }
    }

    core::ptr::null_mut()
}

/// FreeType 2.3 `FT_Get_Module_Interface` (ftobjs.c) — original:
/// `FUN_0804c560` @ 0x0804c560 (24 bytes).
///
/// Delegates to [`ft_get_module`]. A failed lookup returns NULL; otherwise
/// this performs the same nested `module->clazz->module_interface` read as
/// the ARM `ldrne` pair (+0x00 then +0x14). No deviations.
///
/// # Safety
/// `library` and `module_name` must meet [`ft_get_module`]'s requirements.
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
    use core::ptr::{null, null_mut};

    fn library_with_modules(
        count: u32,
        modules: [*mut FtModule; 32],
    ) -> FtLibraryModuleTable {
        FtLibraryModuleTable {
            _memory: null_mut(),
            _generic_data: null_mut(),
            _generic_finalizer: null(),
            _version_major: 0,
            _version_minor: 0,
            _version_patch: 0,
            num_modules: count,
            modules,
        }
    }

    fn module_with_name(name: *const u8) -> (FtModuleClass, FtModule) {
        (
            FtModuleClass {
                module_flags: 0,
                module_size: 0,
                module_name: name,
                module_version: 0,
                module_requires: 0,
                module_interface: null(),
            },
            FtModule { clazz: null() },
        )
    }

    #[test]
    fn module_lookup_rejects_null_arguments() {
        unsafe {
            assert!(ft_get_module(null_mut(), b"truetype\0".as_ptr()).is_null());
            assert!(ft_get_module(1usize as *mut FtLibrary, null()).is_null());
        }
    }

    #[test]
    fn module_lookup_returns_the_first_exact_name_match() {
        unsafe {
            let (class_type1, mut module_type1) = module_with_name(b"type1\0".as_ptr());
            let (class_truetype, mut module_truetype) =
                module_with_name(b"truetype\0".as_ptr());
            module_type1.clazz = &class_type1;
            module_truetype.clazz = &class_truetype;

            let mut modules = [null_mut(); 32];
            modules[0] = &mut module_type1;
            modules[1] = &mut module_truetype;
            let mut library = library_with_modules(2, modules);
            let library_ptr = (&mut library as *mut FtLibraryModuleTable).cast::<FtLibrary>();

            assert!(
                core::ptr::eq(
                    ft_get_module(library_ptr, b"truetype\0".as_ptr()),
                    &mut module_truetype
                )
            );
            assert!(ft_get_module(library_ptr, b"true\0".as_ptr()).is_null());
        }
    }

    #[test]
    fn module_interface_uses_the_ported_module_lookup() {
        unsafe {
            let (mut class, mut module) = module_with_name(b"truetype\0".as_ptr());
            let interface = 0x1234usize as *const c_void;
            class.module_interface = interface;
            module.clazz = &class;

            let mut modules = [null_mut(); 32];
            modules[0] = &mut module;
            let mut library = library_with_modules(1, modules);
            let library_ptr = (&mut library as *mut FtLibraryModuleTable).cast::<FtLibrary>();

            assert_eq!(
                ft_get_module_interface(library_ptr, b"truetype\0".as_ptr()),
                interface
            );
        }
    }
}
