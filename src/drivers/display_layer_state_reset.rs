//! Display-layer state reset — original: `FUN_0828d504` @ `0x0828d504`.
//!
//! Raw `osos.dec` establishes the 120-byte extent: 30 ARM words from
//! `push {r4-r6,lr}` through `pop {r4-r6,pc}` at `0x0828d578`; the next
//! independently linked function begins at `0x0828d57c`. It has five direct
//! call sites: four unconditional `bl` and one predicated `bleq`.
//!
//! The state owns a display at `+0xf4` and a layer index in the low byte at
//! `+0xfc`. Reset obtains that layer, pops its current configuration, and
//! enables it. When its mode word is four, it unregisters each nonzero callback
//! in the three following words, clears those words, then marks mode and layer
//! index absent with `0xffffffff`.
//!
//! Deliberate deviation: layer-configuration pop at `0x0811ff8c` has not yet
//! been ported. Target builds call it at its verified retail address; host
//! tests supply the same ABI through operations below.

use crate::app::global_callback_unregister::global_callback_unregister;
use crate::drivers::display::{display_get_layer, Display};
use crate::drivers::display_layer::layer_enable;

pub type LayerConfigurationPop = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_layer_configuration_pop(layer: *mut u8) -> u32 {
    let pop: LayerConfigurationPop = core::mem::transmute(0x0811_ff8cusize);
    pop(layer)
}

struct DisplayLayerStateResetOps {
    get_layer: unsafe extern "C" fn(*mut Display, u32) -> *mut u8,
    pop_configuration: LayerConfigurationPop,
    enable_layer: unsafe extern "C" fn(*mut u8),
    unregister_callback: unsafe extern "C" fn(u32),
}

#[cfg(target_os = "none")]
const RETAIL_OPS: DisplayLayerStateResetOps = DisplayLayerStateResetOps {
    get_layer: display_get_layer,
    pop_configuration: retail_layer_configuration_pop,
    enable_layer: layer_enable,
    unregister_callback: global_callback_unregister,
};

unsafe fn display_layer_state_reset_with_ops(state: *mut u8, ops: &DisplayLayerStateResetOps) {
    let layer_index = state.add(0xfc).cast::<u32>().read_volatile() & 0xff;
    let display = state.add(0xf4).cast::<u32>().read_volatile() as usize as *mut Display;
    let layer = (core::ptr::read_volatile(core::ptr::addr_of!(ops.get_layer)))(display, layer_index);
    (core::ptr::read_volatile(core::ptr::addr_of!(ops.pop_configuration)))(layer);
    (core::ptr::read_volatile(core::ptr::addr_of!(ops.enable_layer)))(layer);

    if state.add(0x100).cast::<u32>().read_volatile() == 4 {
        for offset in [0x104, 0x108, 0x10c] {
            let callback = state.add(offset).cast::<u32>().read_volatile();
            if callback != 0 {
                (core::ptr::read_volatile(core::ptr::addr_of!(ops.unregister_callback)))(callback);
            }
            state.add(offset).cast::<u32>().write_volatile(0);
        }
    }

    state.add(0x100).cast::<u32>().write_volatile(u32::MAX);
    state.add(0xfc).cast::<u32>().write_volatile(u32::MAX);
}

/// Reset a display-layer state object — original: `FUN_0828d504` @ `0x0828d504`.
///
/// # Safety
/// `state` must point to the retail state layout through offset `0x10c`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn display_layer_state_reset(state: *mut u8) {
    #[cfg(target_os = "none")]
    display_layer_state_reset_with_ops(state, &RETAIL_OPS);

    #[cfg(not(target_os = "none"))]
    panic!("display_layer_state_reset is exercised through its host operations");
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: LazyLock<Mutex<std::vec::Vec<(u8, usize)>>> = LazyLock::new(|| Mutex::new(std::vec::Vec::new()));

    unsafe extern "C" fn get_layer(display: *mut Display, index: u32) -> *mut u8 {
        CALLS.lock().push((0, display as usize));
        CALLS.lock().push((1, index as usize));
        0x1234usize as *mut u8
    }
    unsafe extern "C" fn pop_configuration(layer: *mut u8) -> u32 {
        CALLS.lock().push((2, layer as usize));
        0
    }
    unsafe extern "C" fn enable_layer(layer: *mut u8) { CALLS.lock().push((3, layer as usize)); }
    unsafe extern "C" fn unregister(callback: u32) { CALLS.lock().push((4, callback as usize)); }

    const OPS: DisplayLayerStateResetOps = DisplayLayerStateResetOps {
        get_layer, pop_configuration, enable_layer, unregister_callback: unregister,
    };

    #[test]
    fn mode_four_unregisters_nonzero_callbacks_in_order_and_clears_state() {
        let _guard = TEST_LOCK.lock();
        let mut state = [0u32; 0x110 / 4];
        state[0xfc / 4] = 0xab00_0012;
        state[0xf4 / 4] = 0x5678;
        state[0x100 / 4] = 4;
        state[0x104 / 4] = 0x11;
        state[0x108 / 4] = 0;
        state[0x10c / 4] = 0x33;
        CALLS.lock().clear();

        unsafe { display_layer_state_reset_with_ops(state.as_mut_ptr().cast(), &OPS) };

        assert_eq!(*CALLS.lock(), std::vec![(0, 0x5678), (1, 0x12), (2, 0x1234), (3, 0x1234), (4, 0x11), (4, 0x33)]);
        assert_eq!(state[0x104 / 4], 0);
        assert_eq!(state[0x108 / 4], 0);
        assert_eq!(state[0x10c / 4], 0);
        assert_eq!(state[0x100 / 4], u32::MAX);
        assert_eq!(state[0xfc / 4], u32::MAX);
    }

    #[test]
    fn other_modes_preserve_callback_words_but_reset_mode_and_layer_index() {
        let _guard = TEST_LOCK.lock();
        let mut state = [0u32; 0x110 / 4];
        state[0xfc / 4] = 0xffff_00ff;
        state[0xf4 / 4] = 0x2222;
        state[0x100 / 4] = 3;
        state[0x104 / 4] = 0x11;
        state[0x108 / 4] = 0x22;
        state[0x10c / 4] = 0x33;
        CALLS.lock().clear();

        unsafe { display_layer_state_reset_with_ops(state.as_mut_ptr().cast(), &OPS) };

        assert_eq!(*CALLS.lock(), std::vec![(0, 0x2222), (1, 0xff), (2, 0x1234), (3, 0x1234)]);
        assert_eq!(state[0x104 / 4], 0x11);
        assert_eq!(state[0x108 / 4], 0x22);
        assert_eq!(state[0x10c / 4], 0x33);
        assert_eq!(state[0x100 / 4], u32::MAX);
        assert_eq!(state[0xfc / 4], u32::MAX);
    }
}
