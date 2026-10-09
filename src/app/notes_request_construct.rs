//! `notes_request_construct` — `FUN_0810333c` @ `0x0810333c`.
//!
//! True extent: 104 bytes (96 instruction bytes, literals at 0x0810339c
//! and 0x081033a0); next real function begins at 0x081033a4. Whole-image
//! A32 decoding verifies two inbound plain BLs (0x08178a88, 0x08178c20),
//! zero predicated BLs; the body has four plain BLs, zero predicated BLs.
//! Construct the framework string pair with the supplied context, install
//! vtable 0x0898071c, construct its embedded request at +0x24 using the
//! Notes dispatcher's +0x4ec member, then recover the enclosing object from
//! the returned request. Clear words +0x64/+0x68/+0x6c, store the mode at
//! +0x70, clear +0x71, and register the embedded request with 0x08ad5d44.
//! The callers allocate 0x74 bytes and subsequently fill the three words.
//!
//! Deviations: no behavioral changes. Unported callees remain ARM firmware
//! calls with names describing only verified behavior, not inferred classes.
//! Hosts supply these effects explicitly through `NotesRequestOps`; the
//! firmware entry is not callable on hosts. Target pointer fields stay u32.

use crate::cxx::framework_string_pair_construct::{framework_string_pair_construct, FrameworkStringPair};

pub const NOTES_REQUEST_VTABLE: u32 = 0x0898_071c;
pub const NOTES_REQUEST_REGISTRY: usize = 0x08ad_5d44;

/// External effects of the two unported callees and singleton lookup.
#[derive(Clone, Copy)]
pub struct NotesRequestOps {
    pub dispatcher: unsafe extern "C" fn() -> *mut u8,
    pub embedded_construct: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) -> *mut u8,
    pub register: unsafe extern "C" fn(*mut u8, *mut u8),
}

/// Execute the constructor with explicitly supplied external effects.
///
/// # Safety
/// Storage and the embedded constructor's returned enclosing object must each
/// provide 0x74 writable, word-aligned bytes. Operations must obey their firmware
/// contracts. Dispatcher +0x4ec is formed even when the lookup returns null.
pub unsafe fn notes_request_construct_with_ops(
    storage: *mut u8, context: u32, mode: u8, ops: NotesRequestOps,
) -> *mut u8 {
    let base = framework_string_pair_construct(storage.cast::<FrameworkStringPair>(), context).cast::<u8>();
    base.cast::<u32>().write_volatile(NOTES_REQUEST_VTABLE);
    let dispatcher = (ops.dispatcher)();
    let request = (ops.embedded_construct)(base.add(0x24), base, dispatcher.wrapping_add(0x4ec));
    let object = request.sub(0x24);
    object.add(0x64).cast::<u32>().write_volatile(0);
    object.add(0x68).cast::<u32>().write_volatile(0);
    object.add(0x6c).cast::<u32>().write_volatile(0);
    object.add(0x70).write_volatile(mode);
    object.add(0x71).write_volatile(0);
    (ops.register)(NOTES_REQUEST_REGISTRY as *mut u8, object.add(0x24));
    object
}

/// Construct and register a Notes request using retailOS services.
///
/// # Safety
/// Requires the live retailOS runtime and aligned 0x74-byte storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn notes_request_construct(storage: *mut u8, context: u32, mode: u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        notes_request_construct_with_ops(storage, context, mode, NotesRequestOps {
            dispatcher: crate::app::registry::instance_of_class_4180,
            embedded_construct: core::mem::transmute(0x0828_a0c0usize),
            register: core::mem::transmute(0x0815_bb54usize),
        })
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (storage, context, mode);
        panic!("notes_request_construct requires retailOS; supply NotesRequestOps on hosts")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static mut RETURN_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut EXPECTED_MODE: u8 = 0;
    static mut EXPECTED_CONTEXT: u32 = 0;
    static mut DISPATCHER: *mut u8 = core::ptr::null_mut();
    #[repr(C, align(4))]
    struct Storage([u8; 0x78]);

    unsafe extern "C" fn dispatcher() -> *mut u8 { DISPATCHER }
    unsafe extern "C" fn embedded(request: *mut u8, owner: *mut u8, source: *mut u8) -> *mut u8 {
        assert_eq!(request, owner.add(0x24));
        assert_eq!(source, DISPATCHER.wrapping_add(0x4ec));
        assert_eq!(owner.cast::<u32>().read(), NOTES_REQUEST_VTABLE);
        assert_eq!(owner.add(0x1c).cast::<u32>().read(), EXPECTED_CONTEXT);
        if RETURN_OBJECT.is_null() { request } else { RETURN_OBJECT.add(0x24) }
    }
    unsafe extern "C" fn register(registry: *mut u8, request: *mut u8) {
        assert_eq!(registry as usize, NOTES_REQUEST_REGISTRY);
        let object = request.sub(0x24);
        assert_eq!(object.add(0x64).cast::<u32>().read(), 0);
        assert_eq!(object.add(0x68).cast::<u32>().read(), 0);
        assert_eq!(object.add(0x6c).cast::<u32>().read(), 0);
        assert_eq!(object.add(0x70).read(), EXPECTED_MODE);
        assert_eq!(object.add(0x71).read(), 0);
    }

    #[test]
    fn initializes_before_registration_and_uses_returned_enclosing_object() {
        for relocated in [false, true] {
            for mode in [0, 1, 0x80, 0xff] {
                for context in [0, 0xffff_ffff] {
                    let mut storage = Storage([0xa5; 0x78]);
                    let mut replacement = Storage([0x5a; 0x78]);
                    let mut singleton = Storage([0; 0x78]);
                    unsafe {
                        EXPECTED_MODE = mode;
                        EXPECTED_CONTEXT = context;
                        DISPATCHER = if mode == 0 { core::ptr::null_mut() } else { singleton.0.as_mut_ptr() };
                        RETURN_OBJECT = if relocated { replacement.0.as_mut_ptr() } else { core::ptr::null_mut() };
                        let result = notes_request_construct_with_ops(storage.0.as_mut_ptr(), context, mode,
                            NotesRequestOps { dispatcher, embedded_construct: embedded, register });
                        let expected = if relocated { replacement.0.as_mut_ptr() } else { storage.0.as_mut_ptr() };
                        assert_eq!(result, expected);
                        let marker = if relocated { 0x5a } else { 0xa5 };
                        assert_eq!(result.add(0x63).read(), marker);
                        assert_eq!(core::slice::from_raw_parts(result.add(0x72), 6), &[marker; 6]);
                        if relocated { assert_eq!(&storage.0[0x64..], &[0xa5; 0x14]); }
                    }
                }
            }
        }
    }
}
