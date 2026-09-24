//! Dispatches the configured callback for the FreeType TrueType module.
//!
//! `ft_truetype_module_callback` — original: `FUN_080d9ae4` @ `0x080d9ae4`
//! (60 bytes, `0x080d9ae4..0x080d9b20`; the next independently decoded
//! function begins at `0x080d9b24` after the literal-pool word). The raw ARM
//! has one plain direct `bl` (`FT_Get_Module` at `0x0804c500`) and no
//! predicated direct BL instructions.
//!
//! # Algorithm
//!
//! Dereference the caller's context, find its library through the nested
//! `+0x60/+0x04` fields, and look up the `"truetype"` module. If both that
//! lookup and the context callback at `+0x140` succeed, tail-dispatch the
//! callback with the module as its sole argument; otherwise return NULL.
//!
//! Deliberate deviation: Rust returns normally after the callback rather than
//! reproducing the ARM tail branch. The target-width field relationships are
//! represented by nested `#[repr(C)]` records rather than host byte offsets.

use crate::ft::module::{ft_get_module, FtModule};
use crate::ft::stream::FtLibrary;

const TRUETYPE_MODULE_NAME: &[u8] = b"truetype\0";

type TruetypeModuleCallback = unsafe extern "C" fn(*mut FtModule);

/// Nested state whose library field is at `+0x04` on the 32-bit target.
#[repr(C)]
pub struct FtModuleCallbackLibrary {
    _unknown_00: u32,
    pub library: *mut FtLibrary,
}

/// Context fields read by the retail wrapper.
#[repr(C)]
pub struct FtTruetypeModuleCallbackContext {
    _unknown_00_5f: [u8; 0x60],
    pub library_state: *mut FtModuleCallbackLibrary,
    _unknown_64_13f: [u8; 0xdc],
    pub callback: Option<TruetypeModuleCallback>,
}

/// Looks up the TrueType module and invokes this context's registered callback.
///
/// # Safety
/// `context_slot` must point to a valid context pointer. Its nested library
/// state and every FreeType record inspected by [`ft_get_module`] must be
/// valid. A present callback must accept the returned module.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_truetype_module_callback(
    context_slot: *mut *mut FtTruetypeModuleCallbackContext,
) -> *mut FtModule {
    let context = *context_slot;
    let callback = (*context).callback;
    let library = (*(*context).library_state).library;
    let module = ft_get_module(library, TRUETYPE_MODULE_NAME.as_ptr());

    if !module.is_null() {
        if let Some(callback) = callback {
            callback(module);
        }
    }

    module
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::ft::module::FtModuleClass;
    use core::ffi::c_void;
    use core::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[repr(C)]
    struct LibraryModuleTable {
        _memory: *mut c_void,
        _generic_data: *mut c_void,
        _generic_finalizer: *const c_void,
        _version_major: i32,
        _version_minor: i32,
        _version_patch: i32,
        num_modules: u32,
        modules: [*mut FtModule; 32],
    }

    static CALLBACK_MODULE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_callback(module: *mut FtModule) {
        CALLBACK_MODULE.store(module as usize, Ordering::Relaxed);
    }

    fn context_for(
        library: *mut FtLibrary,
        callback: Option<TruetypeModuleCallback>,
    ) -> (std::boxed::Box<FtModuleCallbackLibrary>, FtTruetypeModuleCallbackContext) {
        let mut library_state = std::boxed::Box::new(FtModuleCallbackLibrary { _unknown_00: 0, library });
        let context = FtTruetypeModuleCallbackContext {
            _unknown_00_5f: [0; 0x60],
            library_state: library_state.as_mut(),
            _unknown_64_13f: [0; 0xdc],
            callback,
        };
        (library_state, context)
    }

    #[test]
    fn returns_null_without_a_truetype_module() {
        let mut table = LibraryModuleTable {
            _memory: null_mut(), _generic_data: null_mut(), _generic_finalizer: null(),
            _version_major: 0, _version_minor: 0, _version_patch: 0,
            num_modules: 0, modules: [null_mut(); 32],
        };
        let (_library_state, mut context) = context_for((&mut table as *mut LibraryModuleTable).cast(), Some(record_callback));
        let mut slot: *mut FtTruetypeModuleCallbackContext = &mut context;
        CALLBACK_MODULE.store(0, Ordering::Relaxed);

        assert!(unsafe { ft_truetype_module_callback(&mut slot) }.is_null());
        assert_eq!(CALLBACK_MODULE.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn returns_module_without_calling_an_absent_callback() {
        let name = b"truetype\0";
        let class = FtModuleClass { module_flags: 0, module_size: 0, module_name: name.as_ptr(), module_version: 0, module_requires: 0, module_interface: null() };
        let mut module = FtModule { clazz: &class };
        let mut table = LibraryModuleTable {
            _memory: null_mut(), _generic_data: null_mut(), _generic_finalizer: null(),
            _version_major: 0, _version_minor: 0, _version_patch: 0,
            num_modules: 1, modules: [null_mut(); 32],
        };
        table.modules[0] = &mut module;
        let (_library_state, mut context) = context_for((&mut table as *mut LibraryModuleTable).cast(), None);
        let mut slot: *mut FtTruetypeModuleCallbackContext = &mut context;

        assert!(unsafe { ft_truetype_module_callback(&mut slot) } == &mut module);
    }

    #[test]
    fn dispatches_callback_with_the_found_module() {
        let name = b"truetype\0";
        let class = FtModuleClass { module_flags: 0, module_size: 0, module_name: name.as_ptr(), module_version: 0, module_requires: 0, module_interface: null() };
        let mut module = FtModule { clazz: &class };
        let mut table = LibraryModuleTable {
            _memory: null_mut(), _generic_data: null_mut(), _generic_finalizer: null(),
            _version_major: 0, _version_minor: 0, _version_patch: 0,
            num_modules: 1, modules: [null_mut(); 32],
        };
        table.modules[0] = &mut module;
        let (_library_state, mut context) = context_for((&mut table as *mut LibraryModuleTable).cast(), Some(record_callback));
        let mut slot: *mut FtTruetypeModuleCallbackContext = &mut context;
        CALLBACK_MODULE.store(0, Ordering::Relaxed);

        assert!(unsafe { ft_truetype_module_callback(&mut slot) } == &mut module);
        assert_eq!(CALLBACK_MODULE.load(Ordering::Relaxed), &mut module as *mut FtModule as usize);
    }
}
