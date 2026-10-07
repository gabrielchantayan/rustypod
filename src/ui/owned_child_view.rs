//! View construction with an owned callback child.

use super::view_base::{ViewBase, ViewSpec, view_base_construct};
use crate::app::resource_chain::ResourceProvider;
use crate::heap::veneers::operator_new;

#[repr(C)]
pub struct OwnedChildView {
    pub base: ViewBase,
    pub child: *mut u8,
    pub flag_26: u8,
    pub padding: [u8; 3],
}

#[cfg(target_os = "none")]
const _: [u8; 0xac] = [0; core::mem::size_of::<OwnedChildView>()];

type BaseConstruct = unsafe extern "C" fn(*mut ViewBase, *mut ResourceProvider, *mut u8, *mut u8, *const ViewSpec) -> *mut ViewBase;
type ChildConstruct = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;
type CallbackConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
pub struct OwnedChildViewOps {
    pub base: BaseConstruct,
    pub allocate: unsafe extern "C" fn(usize) -> *mut u8,
    pub child: ChildConstruct,
    pub callback: CallbackConstruct,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_child(_: *mut u8, _: u32) -> *mut u8 {
    panic!("resident child constructor 0x0839c428 requires a host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_callback(_: *mut u8) -> *mut u8 {
    panic!("resident callback constructor 0x0816f23c requires a host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut OWNED_CHILD_VIEW_OPS: OwnedChildViewOps = OwnedChildViewOps {
    base: view_base_construct,
    allocate: operator_new,
    child: missing_child,
    callback: missing_callback,
};

/// Original `FUN_08147810` @ 0x08147810: 148 bytes, extent
/// [0x08147810, 0x081478a4), including vtable literal 0x08986444.
/// Raw words verify five plain BLs, zero predicated BLs, two virtual BLXs;
/// two incoming plain BLs and zero predicated incoming BLs.
/// Construct the ViewBase, install the derived vtable, clear the child,
/// allocate/construct a 44-byte child with mode 1 and an 8-byte callback,
/// dispatch child slots +0x54(callback) and +0x5c(1), then normalize base
/// flag bit 26 into the derived byte. Return the base constructor result.
/// Deliberate deviations: native child/vtable pointers widen host fixtures;
/// target retains verified resident child constructors, while the base and
/// allocator reuse existing ports. Host-only operation seams permit fixtures.
/// Concrete child class identities remain unknown.
///
/// # Safety
/// Storage and arguments must satisfy `view_base_construct`. Its result must
/// have room for `OwnedChildView`; allocations and virtual methods must obey
/// the resident constructor ABIs and may not invalidate the view.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owned_child_view_construct(
    storage: *mut OwnedChildView,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const ViewSpec,
) -> *mut OwnedChildView {
    #[cfg(target_os = "none")]
    let (base, allocate, child_construct, callback_construct): (BaseConstruct, unsafe extern "C" fn(usize) -> *mut u8, ChildConstruct, CallbackConstruct) = (
        view_base_construct, operator_new,
        core::mem::transmute(0x0839_c428usize),
        core::mem::transmute(0x0816_f23cusize),
    );
    #[cfg(not(target_os = "none"))]
    let (base, allocate, child_construct, callback_construct) = (
        core::ptr::addr_of!(OWNED_CHILD_VIEW_OPS.base).read_volatile(),
        core::ptr::addr_of!(OWNED_CHILD_VIEW_OPS.allocate).read_volatile(),
        core::ptr::addr_of!(OWNED_CHILD_VIEW_OPS.child).read_volatile(),
        core::ptr::addr_of!(OWNED_CHILD_VIEW_OPS.callback).read_volatile(),
    );
    let view = base(storage.cast(), resources, controller, parent, spec).cast::<OwnedChildView>();
    core::ptr::addr_of_mut!((*view).base.vtable).write_volatile(0x0898_6444);
    core::ptr::addr_of_mut!((*view).child).write_volatile(core::ptr::null_mut());
    let child = child_construct(allocate(0x2c), 1);
    core::ptr::addr_of_mut!((*view).child).write_volatile(child);
    let callback = callback_construct(allocate(8));
    let child = core::ptr::addr_of!((*view).child).read_volatile();
    let table = child.cast::<*const usize>().read();
    let attach: unsafe extern "C" fn(*mut u8, *mut u8) = core::mem::transmute(table.add(0x54 / 4).read());
    attach(child, callback);
    let child = core::ptr::addr_of!((*view).child).read_volatile();
    let table = child.cast::<*const usize>().read();
    let enable: unsafe extern "C" fn(*mut u8, u32) = core::mem::transmute(table.add(0x5c / 4).read());
    enable(child, 1);
    let flags = core::ptr::addr_of!((*view).base.flags).read_volatile();
    core::ptr::addr_of_mut!((*view).flag_26).write_volatile(((flags >> 26) & 1) as u8);
    view
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut VIEW: *mut OwnedChildView = core::ptr::null_mut();
    static mut CHILD: [usize; 6] = [0; 6];
    static mut CALLBACK: [usize; 2] = [0; 2];
    static mut FINAL_FLAGS: u32 = 0;
    unsafe extern "C" fn base(_: *mut ViewBase, _: *mut ResourceProvider, _: *mut u8, _: *mut u8, _: *const ViewSpec) -> *mut ViewBase {
        (*VIEW).base.flags = !FINAL_FLAGS;
        VIEW.cast()
    }
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        if size == 44 { core::ptr::addr_of_mut!(CHILD).cast() }
        else { assert_eq!(size, 8); core::ptr::addr_of_mut!(CALLBACK).cast() }
    }
    unsafe extern "C" fn child(storage: *mut u8, mode: u32) -> *mut u8 {
        assert_eq!(mode, 1);
        assert!((*VIEW).child.is_null());
        storage
    }
    unsafe extern "C" fn callback(storage: *mut u8) -> *mut u8 { storage }
    unsafe extern "C" fn attach(_: *mut u8, callback: *mut u8) {
        assert_eq!(callback, core::ptr::addr_of_mut!(CALLBACK).cast());
        (*VIEW).base.flags = FINAL_FLAGS;
    }
    unsafe extern "C" fn enable(_: *mut u8, value: u32) { assert_eq!(value, 1); }

    #[test]
    fn derives_final_flag_and_preserves_tail_and_base_result() {
        let _lock = LOCK.lock();
        unsafe {
            let previous = core::ptr::addr_of!(OWNED_CHILD_VIEW_OPS).read();
            core::ptr::addr_of_mut!(OWNED_CHILD_VIEW_OPS).write(OwnedChildViewOps { base, allocate, child, callback });
            let mut table = [0usize; 24];
            table[21] = attach as *const () as usize;
            table[23] = enable as *const () as usize;
            core::ptr::addr_of_mut!(CHILD).cast::<usize>().write(table.as_ptr() as usize);
            for flags in [0, 1 << 26, !(1 << 26), u32::MAX] {
                let mut result = core::mem::MaybeUninit::<OwnedChildView>::uninit();
                core::ptr::write_bytes(result.as_mut_ptr().cast::<u8>(), 0xa5, core::mem::size_of::<OwnedChildView>());
                VIEW = result.as_mut_ptr();
                FINAL_FLAGS = flags;
                // Base result, not input storage, owns the derived fields.
                let returned = owned_child_view_construct(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null());
                assert_eq!(returned, result.as_mut_ptr());
                assert_eq!((*returned).base.vtable, 0x0898_6444);
                assert_eq!((*returned).flag_26, ((flags >> 26) & 1) as u8);
                assert_eq!((*returned).padding, [0xa5; 3]);
                assert_eq!((*returned).base.word_44, 0xa5a5_a5a5);
                assert_eq!((*returned).child, core::ptr::addr_of_mut!(CHILD).cast());
            }
            core::ptr::addr_of_mut!(OWNED_CHILD_VIEW_OPS).write(previous);
        }
    }
}
