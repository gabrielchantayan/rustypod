//! `vtable_089a8414_construct` — retailOS `FUN_0827c704` @ `0x0827c704`.
//!
//! ## Original
//!
//! Raw `osos.dec` words establish a 64-byte A32 body at
//! `0x0827c704..0x0827c744`; the literal pool word at `0x0827c744` is
//! `0x089a8414`, and the next independently entered function begins at
//! `0x0827c748`. The body has two plain direct `bl` calls, no predicated
//! `bl` calls, and one indirect `blx r1` virtual call (three call sites).
//! It constructs an opaque base, installs vtable `0x089a8414`, invokes its
//! slot +0x28 on the resulting object, then constructs the opaque member at
//! +0xa8 from that result and the supplied payload. The member constructor
//! returns its +0xa8 subobject, so the wrapper rebases it before returning.
//!
//! Deliberate host deviation: the two direct retail callees and target-width
//! vtable dispatch are host-swappable seams; target builds call their verified
//! retail addresses directly.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_BASE_CONSTRUCT: usize = 0x0827_c2ec;
const RETAIL_MEMBER_CONSTRUCT: usize = 0x0827_ca64;
const VTABLE_089A8414: u32 = 0x089a_8414;
const MEMBER_OFFSET_WORDS: usize = 0x2a;

pub type OpaqueBaseConstruct = unsafe extern "C" fn(*mut u32, u32) -> *mut u32;
pub type VtableSlot28 = unsafe extern "C" fn(*mut u32) -> u32;
pub type OpaqueMemberConstruct = unsafe extern "C" fn(*mut u32, u32, *const u8) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_base(storage: *mut u32) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueBaseConstruct>(RETAIL_BASE_CONSTRUCT)(storage, 0)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_member(storage: *mut u32, value: u32, payload: *const u8) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueMemberConstruct>(RETAIL_MEMBER_CONSTRUCT)(storage, value, payload)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn call_slot_28(object: *mut u32) -> u32 {
    let vtable = object.read() as *const usize;
    core::mem::transmute::<usize, VtableSlot28>(vtable.add(10).read())(object)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_construct(storage: *mut u32, _: u32) -> *mut u32 { storage }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_slot_28(_: *mut u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_member_construct(storage: *mut u32, _: u32, _: *const u8) -> *mut u32 { storage }
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_089A8414_BASE_CONSTRUCT: OpaqueBaseConstruct = missing_base_construct;
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_089A8414_SLOT_28: VtableSlot28 = missing_slot_28;
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_089A8414_MEMBER_CONSTRUCT: OpaqueMemberConstruct = missing_member_construct;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_base(storage: *mut u32) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(VTABLE_089A8414_BASE_CONSTRUCT))(storage, 0)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_member(storage: *mut u32, value: u32, payload: *const u8) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(VTABLE_089A8414_MEMBER_CONSTRUCT))(storage, value, payload)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn call_slot_28(object: *mut u32) -> u32 {
    core::ptr::read_volatile(addr_of!(VTABLE_089A8414_SLOT_28))(object)
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_089a8414_construct(storage: *mut u32, payload: *const u8) -> *mut u32 {
    let object = construct_base(storage);
    object.write(VTABLE_089A8414);
    let value = call_slot_28(object);
    construct_member(object.add(MEMBER_OFFSET_WORDS), value, payload).sub(MEMBER_OFFSET_WORDS)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut BASE_ARGUMENT: (*mut u32, u32) = (core::ptr::null_mut(), 1);
    static mut SLOT_ARGUMENT: *mut u32 = core::ptr::null_mut();
    static mut MEMBER_ARGUMENT: (*mut u32, u32, *const u8) = (core::ptr::null_mut(), 0, core::ptr::null());

    unsafe extern "C" fn base(storage: *mut u32, selector: u32) -> *mut u32 { BASE_ARGUMENT = (storage, selector); storage }
    unsafe extern "C" fn slot(object: *mut u32) -> u32 { SLOT_ARGUMENT = object; 0x1234_5678 }
    unsafe extern "C" fn member(storage: *mut u32, value: u32, payload: *const u8) -> *mut u32 {
        MEMBER_ARGUMENT = (storage, value, payload); storage
    }
    unsafe extern "C" fn shifted_base(storage: *mut u32, selector: u32) -> *mut u32 {
        BASE_ARGUMENT = (storage, selector); storage.add(3)
    }
    struct Reset { _lock: MutexGuard<'static, ()>, base: OpaqueBaseConstruct, slot: VtableSlot28, member: OpaqueMemberConstruct }
    impl Drop for Reset { fn drop(&mut self) { unsafe { VTABLE_089A8414_BASE_CONSTRUCT = self.base; VTABLE_089A8414_SLOT_28 = self.slot; VTABLE_089A8414_MEMBER_CONSTRUCT = self.member; } } }
    fn reset() -> Reset { let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner()); unsafe {
        let reset = Reset { _lock: lock, base: VTABLE_089A8414_BASE_CONSTRUCT, slot: VTABLE_089A8414_SLOT_28, member: VTABLE_089A8414_MEMBER_CONSTRUCT };
        VTABLE_089A8414_BASE_CONSTRUCT = base; VTABLE_089A8414_SLOT_28 = slot; VTABLE_089A8414_MEMBER_CONSTRUCT = member;
        BASE_ARGUMENT = (core::ptr::null_mut(), 1); SLOT_ARGUMENT = core::ptr::null_mut(); MEMBER_ARGUMENT = (core::ptr::null_mut(), 0, core::ptr::null()); reset
    }}
    #[test]
    fn constructs_base_installs_vtable_and_rebases_member_result() {
        let _reset = reset();
        let Some(storage) = try_map_u32_slab(hints::VTABLE_089A8414_CONSTRUCT, 0x1000) else { assert!(note_missing_u32_fixture("cxx/vtable_089a8414_construct")); return; };
        unsafe {
            storage.write_bytes(0xa5, 0x1000); let object = storage.cast::<u32>(); let payload = object.add(128).cast::<u8>();
            assert_eq!(vtable_089a8414_construct(object, payload), object);
            assert_eq!(object.read(), VTABLE_089A8414); assert_eq!(BASE_ARGUMENT, (object, 0)); assert_eq!(SLOT_ARGUMENT, object);
            assert_eq!(MEMBER_ARGUMENT, (object.add(MEMBER_OFFSET_WORDS), 0x1234_5678, payload.cast_const()));
            assert_eq!(object.add(1).read(), 0xa5a5_a5a5);
        }
    }
    #[test]
    fn uses_the_base_returned_object_and_forwards_a_null_payload() {
        let _reset = reset();
        let Some(storage) = try_map_u32_slab(hints::VTABLE_089A8414_CONSTRUCT, 0x1000) else { assert!(note_missing_u32_fixture("cxx/vtable_089a8414_construct shifted base")); return; };
        unsafe {
            VTABLE_089A8414_BASE_CONSTRUCT = shifted_base;
            let object = storage.cast::<u32>().add(3);
            assert_eq!(vtable_089a8414_construct(storage.cast(), core::ptr::null()), object);
            assert_eq!(BASE_ARGUMENT, (storage.cast(), 0)); assert_eq!(SLOT_ARGUMENT, object);
            assert_eq!(object.read(), VTABLE_089A8414);
            assert_eq!(MEMBER_ARGUMENT, (object.add(MEMBER_OFFSET_WORDS), 0x1234_5678, core::ptr::null()));
        }
    }
}
