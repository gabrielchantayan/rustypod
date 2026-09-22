//! Constructs the four-word directional-resource record used by the demo-mode
//! controller.
//!
//! # Original
//!
//! `FUN_08286ad4` @ 0x08286ad4 is exactly 160 bytes of code
//! (`0x08286ad4..0x08286b73`); the following three words are its literal pool
//! and 0x08286b80 starts the next function. Raw ARM has five unconditional
//! direct `bl`, one predicated `bleq`, and one indirect `blx` call. It casts
//! the provider's +0x38 owner to class 0x287, resolves the `"DirP"` and
//! `"DIyD"` keys using the current resource twice, then installs the
//! provider's +0x1a8 result and the two resolved values in `out`.
//!
//! # Deliberate deviations
//!
//! The stock `bl 0x08287278` merely initializes the stack record to
//! `(0, 0, 0, !0)` and is inlined. The unresolved direct resolver at
//! 0x0814376c is represented by a target-address call and a host test seam;
//! its recovered behavior, rather than an invented retail name, determines
//! the seam's name.

#[cfg(not(target_os = "none"))]
use core::ptr;
use crate::app::registry::{object_cast_to_class, FrameworkObject};
use crate::heap::veneers::heap_panic;

const REQUIRED_CLASS: u32 = 0x287;
const FIRST_KEY: u32 = 0x7072_4944;
const SECOND_KEY: u32 = 0x6479_4944;

type ResolveResource = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resolve_resource(owner: *mut u8, key: u32, class: u32, current: u32) -> u32 {
    let resolve: ResolveResource = core::mem::transmute(0x0814_376cusize);
    resolve(owner, key, class, current)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_resolver(_: *mut u8, _: u32, _: u32, _: u32) -> u32 {
    panic!("host tests must install the directional-resource resolver seam")
}

#[cfg(not(target_os = "none"))]
pub static mut DIRECTIONAL_RESOURCE_RESOLVER: ResolveResource = missing_resource_resolver;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resolve_resource(owner: *mut u8, key: u32, class: u32, current: u32) -> u32 {
    ptr::read_volatile(ptr::addr_of!(DIRECTIONAL_RESOURCE_RESOLVER))(owner, key, class, current)
}

#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct DirectionalResourceRecord {
    pub object: u32,
    pub first: u32,
    pub current: u32,
    pub second: u32,
}

#[repr(C)]
pub struct DirectionalResourceSourceVtable {
    unresolved: [usize; 92],
    current_resource: unsafe extern "C" fn(*mut DirectionalResourceSource) -> u32,
}
#[repr(C)]
pub struct DirectionalResourceSource { pub vtable: *const DirectionalResourceSourceVtable }

#[repr(C)]
pub struct DirectionalResourceProviderVtable {
    unresolved: [usize; 106],
    construct_object: unsafe extern "C" fn(*mut DirectionalResourceProvider) -> u32,
}
#[repr(C)]
pub struct DirectionalResourceProvider {
    pub vtable: *const DirectionalResourceProviderVtable,
    unresolved_04_to_34: [u32; 13],
    pub owner: *mut FrameworkObject,
    unresolved_3c_to_e8: [u32; 44],
    pub source: *mut DirectionalResourceSource,
}

/// directional_resource_record_construct — original: `FUN_08286ad4` @ 0x08286ad4.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn directional_resource_record_construct(
    out: *mut DirectionalResourceRecord,
    provider: *mut DirectionalResourceProvider,
    _unused_2: u32,
    _unused_3: u32,
) -> *mut DirectionalResourceRecord {
    let owner = object_cast_to_class((*provider).owner, REQUIRED_CLASS);
    if owner.is_null() { heap_panic(); }
    let source = (*provider).source;
    let first = resolve_resource(owner, FIRST_KEY, REQUIRED_CLASS, ((*(*source).vtable).current_resource)(source));
    let second = resolve_resource(owner, SECOND_KEY, REQUIRED_CLASS, ((*(*source).vtable).current_resource)(source));
    (*out).object = ((*(*provider).vtable).construct_object)(provider);
    (*out).first = first;
    (*out).current = ((*(*source).vtable).current_resource)(source);
    (*out).second = second;
    out
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CURRENT: u32 = 0;
    static mut RESOLVES: [(u32, u32, u32); 2] = [(0, 0, 0); 2];
    static mut RESOLVE_COUNT: usize = 0;
    unsafe extern "C" fn cast(object: *mut FrameworkObject, class: u32) -> *mut u8 { assert_eq!(class, REQUIRED_CLASS); object.cast() }
    unsafe extern "C" fn current(_: *mut DirectionalResourceSource) -> u32 { let value = CURRENT; CURRENT += 1; value }
    unsafe extern "C" fn construct(_: *mut DirectionalResourceProvider) -> u32 { 0x1234_5678 }
    unsafe extern "C" fn resolve(owner: *mut u8, key: u32, class: u32, current: u32) -> u32 { RESOLVES[RESOLVE_COUNT] = (key, class, current); RESOLVE_COUNT += 1; owner as usize as u32 ^ current }
    #[test]
    fn resolves_each_key_with_a_fresh_current_resource_and_stamps_the_final_one() {
        let _guard = TEST_LOCK.lock();
        let object_vtable = crate::app::registry::FrameworkObjectVtable { unresolved_00: [0; 5], cast_to_class: cast };
        let mut object = FrameworkObject { vtable: &object_vtable };
        let source_vtable = DirectionalResourceSourceVtable { unresolved: [0; 92], current_resource: current };
        let mut source = DirectionalResourceSource { vtable: &source_vtable };
        let provider_vtable = DirectionalResourceProviderVtable { unresolved: [0; 106], construct_object: construct };
        let mut provider = DirectionalResourceProvider { vtable: &provider_vtable, unresolved_04_to_34: [0; 13], owner: &mut object, unresolved_3c_to_e8: [0; 44], source: &mut source };
        let mut out = DirectionalResourceRecord { object: 99, first: 99, current: 99, second: 99 };
        unsafe {
            CURRENT = 10; RESOLVE_COUNT = 0;
            addr_of_mut!(DIRECTIONAL_RESOURCE_RESOLVER).write(resolve);
            let out_ptr = &mut out as *mut _;
            assert_eq!(directional_resource_record_construct(out_ptr, &mut provider, 7, 8), out_ptr);
            assert_eq!(addr_of!(RESOLVES).read(), [(FIRST_KEY, REQUIRED_CLASS, 10), (SECOND_KEY, REQUIRED_CLASS, 11)]);
            assert_eq!(out, DirectionalResourceRecord { object: 0x1234_5678, first: (&mut object as *mut _ as usize as u32) ^ 10, current: 12, second: (&mut object as *mut _ as usize as u32) ^ 11 });
            addr_of_mut!(DIRECTIONAL_RESOURCE_RESOLVER).write(missing_resource_resolver);
        }
    }
}
