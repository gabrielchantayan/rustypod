//! CFF PostScript hinter callback dispatch.

use crate::ft::module::{ft_get_module, FtModule};
use crate::ft::stream::FtLibrary;

const PSHINTER_MODULE_NAME: &[u8] = b"pshinter\0";

type PshinterModuleCallback = unsafe extern "C" fn(*mut FtModule) -> u32;

/// Calls a CFF state's first PostScript-hinter callback with the `pshinter`
/// module — retailOS `FUN_080d9a98` at load address `0x080d9a98` (64 bytes).
///
/// Raw ARM runs from `0x080d9a98` through the return at `0x080d9ad4`; the
/// adjacent `"pshinter\0"` literal occupies `0x080d9ad8..0x080d9adf`, and
/// `0x080d9ae4` starts the next function. It has one plain internal `bl`
/// (`ft_get_module` at `0x080d9ab4`) and no predicated BL instructions. Raw
/// A32 decoding finds three plain inbound BL sites (`0x080834e8`,
/// `0x0808351c`, and `0x0809045c`) and no predicated inbound BL sites.
///
/// The routine reads the CFF state through target-width words, looks up the
/// `pshinter` module using the face library, and tail-calls word zero of the
/// state callback table with that module. A missing callback table, module, or
/// callback returns zero. Deliberate deviation: the callback table has no
/// established public FreeType type, so it remains a target-word layout rather
/// than an invented Rust structure.
///
/// # Safety
/// `face_slot` must point to the retail target-width face pointer and every
/// non-null pointer reached through offsets `+0x28c`, `+0x7d4`, and `+0x60/+4`
/// must be valid. A nonzero callback word must be callable as
/// `extern "C" fn(*mut FtModule) -> u32`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cff_invoke_pshinter_module_callback(face_slot: *mut u32) -> u32 {
    let face = core::ptr::read_volatile(face_slot) as *mut u8;
    let state = core::ptr::read_volatile(face.add(0x28c).cast::<u32>()) as *mut u8;
    let callback_table = core::ptr::read_volatile(state.add(0x7d4).cast::<u32>()) as *mut u8;
    let face_root = core::ptr::read_volatile(face.add(0x60).cast::<u32>()) as *mut u8;
    let library = core::ptr::read_volatile(face_root.add(4).cast::<u32>()) as *mut FtLibrary;
    let module = ft_get_module(library, PSHINTER_MODULE_NAME.as_ptr());

    if callback_table.is_null() || module.is_null() {
        return 0;
    }

    let callback_word = core::ptr::read_volatile(callback_table.cast::<u32>());
    if callback_word == 0 {
        return 0;
    }
    let Some(callback) = callback_from_target_word(callback_word) else {
        return 0;
    };
    invoke_pshinter_callback(module, callback)
}

#[inline(always)]
unsafe fn invoke_pshinter_callback(module: *mut FtModule, callback: PshinterModuleCallback) -> u32 {
    callback(module)
}


#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn callback_from_target_word(callback_word: u32) -> Option<PshinterModuleCallback> {
    Some(core::mem::transmute::<u32, PshinterModuleCallback>(callback_word))
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn callback_from_target_word(_: u32) -> Option<PshinterModuleCallback> {
    None
}
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CFF_PSHINTER_CALLBACK, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static OBSERVED_MODULE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callback(module: *mut FtModule) -> u32 {
        OBSERVED_MODULE.store(module as usize, Ordering::SeqCst);
        0x9d3
    }

    #[test]
    fn callback_result_and_module_are_propagated() {
        let module = 0x1234usize as *mut FtModule;
        OBSERVED_MODULE.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { invoke_pshinter_callback(module, callback) }, 0x9d3);
        assert_eq!(OBSERVED_MODULE.load(Ordering::SeqCst), module as usize);
    }

    #[test]
    fn missing_pshinter_module_returns_zero_after_target_offset_loads() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("ft/cff_pshinter_callback"));
            return;
        };

        unsafe {
            let base = base as *mut u8;
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            let face = base.add(0x100);
            let face_root = base.add(0x300);
            let state = base.add(0x500);
            base.cast::<u32>().write(face as usize as u32);
            face.add(0x28c).cast::<u32>().write(state as usize as u32);
            face.add(0x60).cast::<u32>().write(face_root as usize as u32);
            state.add(0x7d4).cast::<u32>().write(base.add(0x900) as usize as u32);
            assert_eq!(cff_invoke_pshinter_module_callback(base.cast()), 0);
        }
    }
}
