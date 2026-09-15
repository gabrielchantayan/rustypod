//! Applies the selected UI mode's bounded dimensions to its render state.
//!
//! `ui_apply_mode_dimensions` — original: `FUN_080f8040` @ **0x080f8040**,
//! 104 bytes (`0x080f8040..0x080f80a4`; the next separately entered veneer
//! starts at `0x080f80a8`). Raw ARM contains three unconditional plain `bl`
//! instructions and no predicated `bl`; whole-image inbound-call decoding finds
//! five plain `bl` call sites and no predicated call sites.
//!
//! # Algorithm
//!
//! Notify the mode backend that slot +0x1d is active, apply its four mode
//! bytes (+0x1d..+0x20), then look up the bounded dimension for the mode and
//! variant at +0x1d/+0x1e. Mode zero stores `(28, lookup)` at +0/+4; mode one
//! stores `(lookup, 28)`. Other modes return the lookup result without changing
//! those words. The accepted pair tail-dispatches through `FUN_080f7d44`.
//!
//! # Deliberate deviation
//!
//! The three relocated-runtime operations and the `FUN_080f7d44` tail target
//! have no recovered names in `names.yaml`. Their raw ABIs are retained as
//! volatile dispatch seams: ARM calls their retail IRAM-mirror addresses, while
//! host tests install recorders. No callee identity is asserted.

use core::ptr;

const MODE_OFFSET: usize = 0x1d;
const VARIANT_OFFSET: usize = 0x1e;
const MODE_BYTE_2_OFFSET: usize = 0x1f;
const MODE_BYTE_3_OFFSET: usize = 0x20;
const DIMENSION_OFFSET: usize = 0x1c;
const WIDTH_OFFSET: usize = 0;
const HEIGHT_OFFSET: usize = 4;
const MAX_DIMENSION: u32 = 28;

pub type ModeActivate = unsafe extern "C" fn(u32, u32);
pub type ModeApply = unsafe extern "C" fn(u32, u32, u32, u32);
pub type ModeDimension = unsafe extern "C" fn(u32, u32) -> u32;
pub type DimensionsApply = unsafe extern "C" fn(*mut u8, u32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_mode_activate(mode: u32, active: u32) {
    core::mem::transmute::<usize, ModeActivate>(0x2200_881cusize)(mode, active)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_mode_apply(mode: u32, variant: u32, byte_2: u32, byte_3: u32) {
    core::mem::transmute::<usize, ModeApply>(0x2200_8744usize)(mode, variant, byte_2, byte_3)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_mode_dimension(mode: u32, variant: u32) -> u32 {
    core::mem::transmute::<usize, ModeDimension>(0x2200_87bcusize)(mode, variant)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_dimensions_apply(state: *mut u8, width: u32, height: u32) -> u32 {
    core::mem::transmute::<usize, DimensionsApply>(0x080f_7d44usize)(state, width, height)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mode_activate(_: u32, _: u32) { panic!("ui_apply_mode_dimensions requires 0x2200881c") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mode_apply(_: u32, _: u32, _: u32, _: u32) { panic!("ui_apply_mode_dimensions requires 0x22008744") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mode_dimension(_: u32, _: u32) -> u32 { panic!("ui_apply_mode_dimensions requires 0x220087bc") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dimensions_apply(_: *mut u8, _: u32, _: u32) -> u32 { panic!("ui_apply_mode_dimensions requires FUN_080f7d44") }

#[cfg(target_os = "none")]
pub static mut MODE_ACTIVATE: ModeActivate = retail_mode_activate;
#[cfg(not(target_os = "none"))]
pub static mut MODE_ACTIVATE: ModeActivate = missing_mode_activate;
#[cfg(target_os = "none")]
pub static mut MODE_APPLY: ModeApply = retail_mode_apply;
#[cfg(not(target_os = "none"))]
pub static mut MODE_APPLY: ModeApply = missing_mode_apply;
#[cfg(target_os = "none")]
pub static mut MODE_DIMENSION: ModeDimension = retail_mode_dimension;
#[cfg(not(target_os = "none"))]
pub static mut MODE_DIMENSION: ModeDimension = missing_mode_dimension;
#[cfg(target_os = "none")]
pub static mut DIMENSIONS_APPLY: DimensionsApply = retail_dimensions_apply;
#[cfg(not(target_os = "none"))]
pub static mut DIMENSIONS_APPLY: DimensionsApply = missing_dimensions_apply;

/// # Safety
/// `state` must be readable through +0x20 and writable as u32 words at +0/+4.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_apply_mode_dimensions(state: *mut u8) -> u32 {
    let mode = state.add(MODE_OFFSET).read() as u32;
    let variant = state.add(VARIANT_OFFSET).read() as u32;
    let activate = ptr::read_volatile(ptr::addr_of!(MODE_ACTIVATE));
    activate(mode, 1);
    let apply = ptr::read_volatile(ptr::addr_of!(MODE_APPLY));
    apply(mode, variant, state.add(MODE_BYTE_2_OFFSET).read() as u32, state.add(MODE_BYTE_3_OFFSET).read() as u32);
    let dimension = ptr::read_volatile(ptr::addr_of!(MODE_DIMENSION))(mode, variant);
    state.add(DIMENSION_OFFSET).write(dimension as u8);
    let (width, height) = match variant {
        0 => (MAX_DIMENSION, dimension),
        1 => (dimension, MAX_DIMENSION),
        _ => return dimension,
    };
    (state.add(WIDTH_OFFSET) as *mut u32).write(width);
    (state.add(HEIGHT_OFFSET) as *mut u32).write(height);
    ptr::read_volatile(ptr::addr_of!(DIMENSIONS_APPLY))(state, width, height)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(u32, u32, u32, u32); 3] = [(0, 0, 0, 0); 3];
    static mut TAIL: (*mut u8, u32, u32) = (ptr::null_mut(), 0, 0);
    struct Restore;
    impl Drop for Restore { fn drop(&mut self) { unsafe { ptr::addr_of_mut!(MODE_ACTIVATE).write_volatile(missing_mode_activate); ptr::addr_of_mut!(MODE_APPLY).write_volatile(missing_mode_apply); ptr::addr_of_mut!(MODE_DIMENSION).write_volatile(missing_mode_dimension); ptr::addr_of_mut!(DIMENSIONS_APPLY).write_volatile(missing_dimensions_apply); } } }
    unsafe extern "C" fn activate(a: u32, b: u32) { CALLS[0] = (a, b, 0, 0); }
    unsafe extern "C" fn apply(a: u32, b: u32, c: u32, d: u32) { CALLS[1] = (a, b, c, d); }
    unsafe extern "C" fn lookup(a: u32, b: u32) -> u32 { CALLS[2] = (a, b, 0, 0); 17 }
    unsafe extern "C" fn tail(state: *mut u8, width: u32, height: u32) -> u32 { TAIL = (state, width, height); 0xfeed_c0de }
    unsafe fn install() { ptr::addr_of_mut!(MODE_ACTIVATE).write_volatile(activate); ptr::addr_of_mut!(MODE_APPLY).write_volatile(apply); ptr::addr_of_mut!(MODE_DIMENSION).write_volatile(lookup); ptr::addr_of_mut!(DIMENSIONS_APPLY).write_volatile(tail); CALLS = [(0, 0, 0, 0); 3]; TAIL = (ptr::null_mut(), 0, 0); }
    #[test]
    fn applies_lookup_as_height_for_variant_zero() { let _lock = LOCK.lock(); let _restore = Restore; let mut state = [0u8; 0x24]; unsafe { install(); state[MODE_OFFSET] = 2; state[VARIANT_OFFSET] = 0; state[MODE_BYTE_2_OFFSET] = 3; state[MODE_BYTE_3_OFFSET] = 4; assert_eq!(ui_apply_mode_dimensions(state.as_mut_ptr()), 0xfeed_c0de); assert_eq!(CALLS, [(2, 1, 0, 0), (2, 0, 3, 4), (2, 0, 0, 0)]); assert_eq!(*(state.as_ptr() as *const u32), 28); assert_eq!(*(state.as_ptr().add(4) as *const u32), 17); assert_eq!(TAIL, (state.as_mut_ptr(), 28, 17)); } }
    #[test]
    fn variant_one_swaps_dimensions_and_other_variant_skips_tail() { let _lock = LOCK.lock(); let _restore = Restore; let mut state = [0u8; 0x24]; unsafe { install(); state[MODE_OFFSET] = 1; state[VARIANT_OFFSET] = 1; assert_eq!(ui_apply_mode_dimensions(state.as_mut_ptr()), 0xfeed_c0de); assert_eq!(*(state.as_ptr() as *const u32), 17); assert_eq!(*(state.as_ptr().add(4) as *const u32), 28); state[VARIANT_OFFSET] = 2; assert_eq!(ui_apply_mode_dimensions(state.as_mut_ptr()), 17); assert_eq!(TAIL, (state.as_mut_ptr(), 17, 28)); } }
}
