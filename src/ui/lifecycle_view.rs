//! Constructor for an as-yet unnamed lifecycle-aware view class.

use super::view_base::{view_base_construct, ViewBase, ViewSpec};
use crate::app::resource_chain::ResourceProvider;
use crate::libc::iram_veneers::iram_memcpy_veneer;

const LIFECYCLE_VIEW_VTABLE: u32 = 0x0898_9b70;
const DERIVED_VTABLE_OFFSET: usize = 0xa4;
const SPEC_MODE_OFFSET: usize = 0x58;
const MODE_OFFSET: usize = 0xa8;
const INITIAL_DATA_OFFSET: usize = 0xaa;
const INITIAL_DATA_SOURCE: *const u8 = 0x083e_2e3e as *const u8;
const INITIAL_DATA_LEN: usize = 10;
const FIRST_STATE_OFFSET: usize = 0xb4;
const FIRST_STATE_WORDS: usize = 7;
const FIRST_ARRAY_OFFSET: usize = 0x148;
const SECOND_ARRAY_OFFSET: usize = 0xd0;
const THIRD_ARRAY_OFFSET: usize = 0x1c0;
const ARRAY_WORDS: usize = 30;

/// The constructor's one unported direct callee, `FUN_08198ae0` @
/// 0x08198ae0. Its only verified effects here are setting byte +0xa9 and,
/// for mode zero, performing further view registration; its class-specific
/// identity remains unknown.
#[derive(Clone, Copy)]
pub struct LifecycleViewOps {
    pub initialize_derived_state: unsafe extern "C" fn(*mut u8, u32),
    pub copy_initial_data: unsafe extern "C" fn(*mut u8, *const u8, usize),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_initialize_derived_state(view: *mut u8, mode: u32) {
    let initialize: unsafe extern "C" fn(*mut u8, u32) = unsafe { core::mem::transmute(0x0819_8ae0usize) };
    unsafe { initialize(view, mode) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initialize_derived_state(_view: *mut u8, _mode: u32) {
    panic!("lifecycle_view_construct requires FUN_08198ae0")
}

unsafe extern "C" fn copy_initial_data(destination: *mut u8, source: *const u8, length: usize) {
    unsafe { iram_memcpy_veneer(destination, source, length); }
}

pub const DEFAULT_LIFECYCLE_VIEW_OPS: LifecycleViewOps = LifecycleViewOps {
    #[cfg(target_os = "none")]
    initialize_derived_state: firmware_initialize_derived_state,
    #[cfg(not(target_os = "none"))]
    initialize_derived_state: missing_initialize_derived_state,
    copy_initial_data,
};

/// Active indirect operations for the unported initializer and host-only
/// replacement of the fixed initial-data copy.
pub static mut LIFECYCLE_VIEW_OPS: LifecycleViewOps = DEFAULT_LIFECYCLE_VIEW_OPS;

#[cfg(test)]
pub(crate) static LIFECYCLE_VIEW_OPS_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// lifecycle_view_construct — original: `FUN_08198f88` @ **0x08198f88**
/// (180 bytes, `0x08198f88..0x0819903c`; the next function starts at
/// `0x08199044` after the two literal-pool words). Raw ARM decoding finds
/// three unconditional `bl` calls (0x0826f26c, 0x08198ae0, and ROM
/// `__rt_memcpy` through 0x08037db0), zero predicated `bl` calls, and two
/// predicated `blt` loop back-edges.
///
/// Chains the 0xa4-byte grand-base view constructor, plants the derived
/// vtable, derives a one-byte mode from spec +0x58, initializes derived
/// state, copies ten fixed firmware bytes to +0xaa, then clears seven state
/// words and three 30-word arrays. Returns its input object.
///
/// Deliberate deviations: `FUN_08198ae0` has no established class identity,
/// so it is an ABI seam named only for its verified initializer role. The
/// fixed source at 0x083e2e3e lies in the still-undecrypted image region;
/// target builds preserve the exact ROM memcpy call, while host tests replace
/// only that copy operation to observe its address and length.
///
/// # Safety
/// `view` must reference writable storage through +0x238; `spec` must be a
/// valid [`ViewSpec`], and the installed operations must accept the object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn lifecycle_view_construct(
    view: *mut u8,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const ViewSpec,
) -> *mut u8 {
    unsafe {
        view_base_construct(view.cast::<ViewBase>(), resources, controller, parent, spec);
        view.add(DERIVED_VTABLE_OFFSET).cast::<u32>().write_volatile(LIFECYCLE_VIEW_VTABLE);
        let mode = spec.cast::<u8>().add(SPEC_MODE_OFFSET).read_volatile() as u32;
        view.add(MODE_OFFSET).write_volatile(mode as u8);
        let initialize = core::ptr::addr_of!(LIFECYCLE_VIEW_OPS.initialize_derived_state).read_volatile();
        initialize(view, u32::from(mode == 2));
        let copy = core::ptr::addr_of!(LIFECYCLE_VIEW_OPS.copy_initial_data).read_volatile();
        copy(view.add(INITIAL_DATA_OFFSET), INITIAL_DATA_SOURCE, INITIAL_DATA_LEN);
        for word in 0..FIRST_STATE_WORDS {
            view.add(FIRST_STATE_OFFSET + word * 4).cast::<u32>().write_volatile(0);
        }
        for word in 0..ARRAY_WORDS {
            view.add(FIRST_ARRAY_OFFSET + word * 4).cast::<u32>().write_volatile(0);
            view.add(SECOND_ARRAY_OFFSET + word * 4).cast::<u32>().write_volatile(0);
            view.add(THIRD_ARRAY_OFFSET + word * 4).cast::<u32>().write_volatile(0);
        }
        view
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::view_base::{ViewBaseOps, VIEW_BASE_OPS, VIEW_BASE_RESOURCE_OPS_TEST_LOCK};
    use core::ptr;

    static mut INITIALIZED_VIEW: *mut u8 = ptr::null_mut();
    #[repr(align(4))]
    struct Storage([u8; 0x238]);

    static mut INITIALIZED_MODE: u32 = u32::MAX;
    static mut COPY_ARGUMENTS: (*mut u8, *const u8, usize) = (ptr::null_mut(), ptr::null(), 0);

    unsafe extern "C" fn construct_linkage_base(view: *mut ViewBase, _parent: *mut u8, _create_link: u32) -> *mut ViewBase { view }
    unsafe extern "C" fn initialize_view_base(_view: *mut ViewBase, _controller: *mut u8, _spec: *const ViewSpec) {}
    unsafe extern "C" fn initialize_derived_state(view: *mut u8, mode: u32) {
        unsafe { INITIALIZED_VIEW = view; INITIALIZED_MODE = mode; }
    }
    unsafe extern "C" fn record_copy(destination: *mut u8, source: *const u8, length: usize) {
        unsafe { COPY_ARGUMENTS = (destination, source, length); }
    }

    #[test]
    fn constructs_and_clears_all_derived_state_for_both_mode_paths() {
        let _derived_guard = LIFECYCLE_VIEW_OPS_TEST_LOCK.lock();
        let _base_guard = VIEW_BASE_RESOURCE_OPS_TEST_LOCK.lock();
        let original_derived = unsafe { LIFECYCLE_VIEW_OPS };
        let original_base = unsafe { VIEW_BASE_OPS };
        unsafe {
            LIFECYCLE_VIEW_OPS = LifecycleViewOps { initialize_derived_state, copy_initial_data: record_copy };
            VIEW_BASE_OPS = ViewBaseOps { construct_linkage_base, initialize: initialize_view_base };
        }
        for &(mode, expected_initialize_mode) in &[(0u8, 0u32), (2, 1), (0xff, 0)] {
            let mut storage = Storage([0xa5u8; 0x238]);
            let mut spec: ViewSpec = unsafe { core::mem::zeroed() };
            unsafe { (ptr::addr_of_mut!(spec).cast::<u8>().add(SPEC_MODE_OFFSET)).write(mode); }
            unsafe {
                INITIALIZED_VIEW = ptr::null_mut();
                INITIALIZED_MODE = u32::MAX;
                COPY_ARGUMENTS = (ptr::null_mut(), ptr::null(), 0);
                assert_eq!(lifecycle_view_construct(storage.0.as_mut_ptr(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), &spec), storage.0.as_mut_ptr());
                assert_eq!(INITIALIZED_VIEW, storage.0.as_mut_ptr());
                assert_eq!(INITIALIZED_MODE, expected_initialize_mode);
                assert_eq!(COPY_ARGUMENTS, (storage.0.as_mut_ptr().add(INITIAL_DATA_OFFSET), INITIAL_DATA_SOURCE, INITIAL_DATA_LEN));
                assert_eq!((storage.0.as_ptr().add(DERIVED_VTABLE_OFFSET) as *const u32).read_volatile(), LIFECYCLE_VIEW_VTABLE);
                assert_eq!(storage.0[MODE_OFFSET], mode);
                for offset in FIRST_STATE_OFFSET..FIRST_STATE_OFFSET + FIRST_STATE_WORDS * 4 { assert_eq!(storage.0[offset], 0); }
                for offset in [FIRST_ARRAY_OFFSET, SECOND_ARRAY_OFFSET, THIRD_ARRAY_OFFSET] {
                    for byte in offset..offset + ARRAY_WORDS * 4 { assert_eq!(storage.0[byte], 0); }
                }
            }
        }
        unsafe { LIFECYCLE_VIEW_OPS = original_derived; VIEW_BASE_OPS = original_base; }
    }
}
