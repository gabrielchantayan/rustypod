//! Dispatches a context-specific FreeType module callback.
//!
//! `ft_module_callback_dispatch` — original: `FUN_080d7168` @ `0x080d7168`
//! (60 bytes, `0x080d7168..0x080d71a4`; its module-name literal is at
//! `0x080d71a4`, and the next function begins at `0x080d71a8`). The raw ARM
//! has one plain direct `bl` (`FT_Get_Module` at `0x0804c500`) and no
//! predicated direct BL instructions. It has three plain inbound BL call sites
//! and no predicated inbound BL call sites.
//!
//! # Algorithm
//!
//! Load the FreeType library through the context's `+0x60/+0x04` fields, look
//! up the module named by the resident literal `0x0891da78`, then tail-dispatch
//! word zero of the context's `+0x210` callback table when both are non-null.
//! Otherwise return the module lookup result. Deliberate deviation: Rust
//! returns normally after the callback rather than reproducing the ARM tail
//! branch; host builds use an injectable lookup seam because the resident
//! module-name address is not mapped there.

use crate::ft::module::{ft_get_module, FtModule};
use crate::ft::stream::FtLibrary;

const MODULE_NAME_ADDRESS: *const u8 = 0x0891_da78usize as *const u8;

type ModuleCallback = unsafe extern "C" fn(*mut FtModule) -> *mut FtModule;
type ModuleLookup = unsafe extern "C" fn(*mut FtLibrary, *const u8) -> *mut FtModule;

/// Target-width nested state whose library is at `+0x04`.
#[repr(C)]
pub struct FtModuleCallbackLibrary {
    _unknown_00: u32,
    pub library: *mut FtLibrary,
}

/// Target-width callback table read at context `+0x210`.
#[repr(C)]
pub struct FtModuleCallbackTable {
    pub callback: Option<ModuleCallback>,
}

/// Context fields read by the retail dispatcher.
#[repr(C)]
pub struct FtModuleCallbackDispatchContext {
    _unknown_00_5f: [u8; 0x60],
    pub library_state: *mut FtModuleCallbackLibrary,
    _unknown_64_20f: [u8; 0x1ac],
    pub callback_table: *const FtModuleCallbackTable,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn module_lookup(library: *mut FtLibrary) -> *mut FtModule {
    ft_get_module(library, MODULE_NAME_ADDRESS)
}

#[cfg(not(target_os = "none"))]
static mut MODULE_LOOKUP: ModuleLookup = host_module_lookup;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_module_lookup(_: *mut FtLibrary, _: *const u8) -> *mut FtModule {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn module_lookup(library: *mut FtLibrary) -> *mut FtModule {
    core::ptr::read_volatile(core::ptr::addr_of!(MODULE_LOOKUP))(library, MODULE_NAME_ADDRESS)
}

/// Looks up the context's module and dispatches its callback table.
///
/// # Safety
/// `context_slot` must point to a valid context pointer; its nested library
/// state must be valid. When the lookup succeeds, a non-null callback table
/// and callback must accept the returned module.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_module_callback_dispatch(
    context_slot: *mut *mut FtModuleCallbackDispatchContext,
) -> *mut FtModule {
    let context = *context_slot;
    let callback_table = (*context).callback_table;
    let library = (*(*context).library_state).library;
    let module = module_lookup(library);

    if !module.is_null() && !callback_table.is_null() {
        if let Some(callback) = (*callback_table).callback {
            return callback(module);
        }
    }

    module
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static LOOKUP_MODULE: AtomicUsize = AtomicUsize::new(0);
    static CALLBACK_MODULE: AtomicUsize = AtomicUsize::new(0);
    static CALLBACK_RESULT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn lookup(_: *mut FtLibrary, module_name: *const u8) -> *mut FtModule {
        assert_eq!(module_name, MODULE_NAME_ADDRESS);
        LOOKUP_MODULE.load(Ordering::Relaxed) as *mut FtModule
    }

    unsafe extern "C" fn callback(module: *mut FtModule) -> *mut FtModule {
        CALLBACK_MODULE.store(module as usize, Ordering::Relaxed);
        CALLBACK_RESULT.load(Ordering::Relaxed) as *mut FtModule
    }

    fn context_for(
        callback_table: *const FtModuleCallbackTable,
    ) -> (std::boxed::Box<FtModuleCallbackLibrary>, FtModuleCallbackDispatchContext) {
        let mut library_state = std::boxed::Box::new(FtModuleCallbackLibrary {
            _unknown_00: 0,
            library: core::ptr::null_mut(),
        });
        let context = FtModuleCallbackDispatchContext {
            _unknown_00_5f: [0; 0x60],
            library_state: library_state.as_mut(),
            _unknown_64_20f: [0; 0x1ac],
            callback_table,
        };
        (library_state, context)
    }

    #[test]
    fn returns_null_without_a_module() {
        let _lock = TEST_LOCK.lock();
        unsafe { MODULE_LOOKUP = lookup; }
        LOOKUP_MODULE.store(0, Ordering::Relaxed);
        let (_library_state, mut context) = context_for(core::ptr::null());
        let mut slot: *mut FtModuleCallbackDispatchContext = &mut context;

        assert!(unsafe { ft_module_callback_dispatch(&mut slot) }.is_null());
    }

    #[test]
    fn returns_module_without_a_callback_table() {
        let _lock = TEST_LOCK.lock();
        unsafe { MODULE_LOOKUP = lookup; }
        let mut module = FtModule { clazz: core::ptr::null() };
        LOOKUP_MODULE.store((&mut module as *mut FtModule) as usize, Ordering::Relaxed);
        let (_library_state, mut context) = context_for(core::ptr::null());
        let mut slot: *mut FtModuleCallbackDispatchContext = &mut context;

        assert!(unsafe { ft_module_callback_dispatch(&mut slot) } == &mut module);
    }

    #[test]
    fn dispatches_callback_and_returns_its_result() {
        let _lock = TEST_LOCK.lock();
        unsafe { MODULE_LOOKUP = lookup; }
        let mut module = FtModule { clazz: core::ptr::null() };
        let mut result = FtModule { clazz: core::ptr::null() };
        LOOKUP_MODULE.store((&mut module as *mut FtModule) as usize, Ordering::Relaxed);
        CALLBACK_MODULE.store(0, Ordering::Relaxed);
        CALLBACK_RESULT.store((&mut result as *mut FtModule) as usize, Ordering::Relaxed);
        let table = FtModuleCallbackTable { callback: Some(callback) };
        let (_library_state, mut context) = context_for(&table);
        let mut slot: *mut FtModuleCallbackDispatchContext = &mut context;

        assert!(unsafe { ft_module_callback_dispatch(&mut slot) } == &mut result);
        assert_eq!(CALLBACK_MODULE.load(Ordering::Relaxed), &mut module as *mut FtModule as usize);
    }
}
