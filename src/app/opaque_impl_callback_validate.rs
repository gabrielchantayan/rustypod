//! `opaque_impl_callback_validate` — original: `FUN_081f92a4` @ `0x081f92a4`
//! (**176 bytes**, `0x081f92a4..0x081f9350`; the next separately linked entry
//! starts at `0x081f9354`). Decoding every ARM `B`/`BL` immediate in
//! `work/firmware/osos.dec` finds exactly four direct inbound `bl` calls, all
//! unconditional: `0x0821dcd4`, `0x0821e070`, `0x0821e8dc`, and `0x0821f018`.
//! There are no predicated direct `bl` calls.
//!
//! The owner has a nullable implementation pointer at target offset `+0x1c`.
//! Its opaque vtable predicates at `+0xf0`, `+0x110`, and `+0x114` are queried
//! in order. When all return zero, the result is the opaque `+0xec` callback's
//! result. Otherwise, the function default-constructs a stack `StringObject`,
//! sends it to callback `+0x7c`, returns one exactly when that callback left a
//! nonempty string, and destroys the temporary. The virtual targets have no
//! recovered identities, so the host representation is an injectable slot
//! table rather than invented callees. On target, each slot is called from the
//! serialized vtable word at its observed target offset.
//!
//! Deliberate deviation: host tests map a raw-u32 owner fixture, so its
//! target-width implementation word stays at target offset `+0x1c`; the
//! opaque virtual interface itself is represented by an injectable callback
//! seam rather than invented callees.

use crate::cxx::string_object::{
    string_default_construct, string_object_destroy, string_object_is_empty, StringObject,
};

const IMPLEMENTATION_OFFSET: usize = 0x1c;
const SLOT_DESCRIBE: usize = 0x7c / 4;
const SLOT_FALLBACK: usize = 0xec / 4;
const SLOT_PREDICATE_FIRST: usize = 0xf0 / 4;
const SLOT_PREDICATE_SECOND: usize = 0x110 / 4;
const SLOT_PREDICATE_THIRD: usize = 0x114 / 4;

type Predicate = unsafe extern "C" fn(*mut u8) -> i32;
type Describe = unsafe extern "C" fn(*mut u8, *mut StringObject);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_predicate_false(_implementation: *mut u8) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_describe_empty(_implementation: *mut u8, _out: *mut StringObject) {}

/// Host model of the implementation's unidentified virtual slots. Each field
/// preserves the observed target slot position without assigning a callee name.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct OpaqueImplementationCallbackOps {
    pub predicate_f0: Predicate,
    pub predicate_110: Predicate,
    pub predicate_114: Predicate,
    pub fallback_ec: Predicate,
    pub describe_7c: Describe,
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_IMPLEMENTATION_CALLBACK_OPS: OpaqueImplementationCallbackOps =
    OpaqueImplementationCallbackOps {
        predicate_f0: host_predicate_false,
        predicate_110: host_predicate_false,
        predicate_114: host_predicate_false,
        fallback_ec: host_predicate_false,
        describe_7c: host_describe_empty,
    };

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn vtable_predicate(implementation: *mut u8, slot: usize) -> Predicate {
    let vtable = *(implementation as *const *const usize);
    core::mem::transmute(*vtable.add(slot))
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn vtable_describe(implementation: *mut u8) -> Describe {
    let vtable = *(implementation as *const *const usize);
    core::mem::transmute(*vtable.add(SLOT_DESCRIBE))
}

/// # Safety
/// `owner` must be readable through target offset `+0x1c`. A non-NULL
/// implementation must have callable vtable words at `+0x7c`, `+0xec`,
/// `+0xf0`, `+0x110`, and `+0x114`; the retail code has no guards for them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_impl_callback_validate(owner: *mut u8) -> i32 {
    let implementation = *((owner as *const u32).add(IMPLEMENTATION_OFFSET / 4)) as usize as *mut u8;

    if implementation.is_null() {
        return 0;
    }

    #[cfg(target_os = "none")]
    let first = vtable_predicate(implementation, SLOT_PREDICATE_FIRST)(implementation);
    #[cfg(not(target_os = "none"))]
    let first = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_IMPLEMENTATION_CALLBACK_OPS.predicate_f0))(implementation);
    if first == 0 {
        #[cfg(target_os = "none")]
        let second = vtable_predicate(implementation, SLOT_PREDICATE_SECOND)(implementation);
        #[cfg(not(target_os = "none"))]
        let second = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_IMPLEMENTATION_CALLBACK_OPS.predicate_110))(implementation);
        if second == 0 {
            #[cfg(target_os = "none")]
            let third = vtable_predicate(implementation, SLOT_PREDICATE_THIRD)(implementation);
            #[cfg(not(target_os = "none"))]
            let third = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_IMPLEMENTATION_CALLBACK_OPS.predicate_114))(implementation);
            if third == 0 {
                #[cfg(target_os = "none")]
                return vtable_predicate(implementation, SLOT_FALLBACK)(implementation);
                #[cfg(not(target_os = "none"))]
                return core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_IMPLEMENTATION_CALLBACK_OPS.fallback_ec))(implementation);
            }
        }
    }

    let mut description = core::mem::MaybeUninit::<StringObject>::uninit();
    let description = string_default_construct(description.as_mut_ptr());
    #[cfg(target_os = "none")]
    vtable_describe(implementation)(implementation, description);
    #[cfg(not(target_os = "none"))]
    core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_IMPLEMENTATION_CALLBACK_OPS.describe_7c))(implementation, description);
    let result = (!string_object_is_empty(description)) as i32;
    string_object_destroy(description);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u8; 5] = [0; 5];
    static mut RESULTS: [i32; 4] = [0; 4];
    static mut DESCRIBE_NONEMPTY: bool = false;

    unsafe extern "C" fn predicate_f0(_implementation: *mut u8) -> i32 { CALLS[0] += 1; RESULTS[0] }
    unsafe extern "C" fn predicate_110(_implementation: *mut u8) -> i32 { CALLS[1] += 1; RESULTS[1] }
    unsafe extern "C" fn predicate_114(_implementation: *mut u8) -> i32 { CALLS[2] += 1; RESULTS[2] }
    unsafe extern "C" fn fallback_ec(_implementation: *mut u8) -> i32 { CALLS[3] += 1; RESULTS[3] }
    unsafe extern "C" fn describe_7c(_implementation: *mut u8, out: *mut StringObject) {
        CALLS[4] += 1;
        if DESCRIBE_NONEMPTY { (*out).payload = b"x\0".as_ptr() as *mut u8; }
    }

    unsafe fn install() {
        OPAQUE_IMPLEMENTATION_CALLBACK_OPS = OpaqueImplementationCallbackOps {
            predicate_f0, predicate_110, predicate_114, fallback_ec, describe_7c,
        };
        CALLS = [0; 5]; RESULTS = [0; 4]; DESCRIBE_NONEMPTY = false;
    }

    unsafe fn owner_with_implementation(implementation: *mut u8) -> Option<*mut u8> {
        let owner = try_map_u32_slab(hints::OPAQUE_IMPL_CALLBACK_VALIDATE, 0x1000)?;
        owner.write_bytes(0, 0x1000);
        owner.cast::<u32>().add(IMPLEMENTATION_OFFSET / 4).write(implementation as usize as u32);
        Some(owner.cast())
    }

    #[test]
    fn null_implementation_returns_zero_without_dispatch() {
        let _guard = OPS_LOCK.lock();
        let Some(owner) = (unsafe { owner_with_implementation(core::ptr::null_mut()) }) else { assert!(note_missing_u32_fixture("app/opaque_impl_callback_validate")); return; };
        unsafe { install(); assert_eq!(opaque_impl_callback_validate(owner), 0); assert_eq!(CALLS, [0; 5]); }
    }

    #[test]
    fn all_clear_predicates_return_fallback() {
        let _guard = OPS_LOCK.lock();
        let Some(owner) = (unsafe { owner_with_implementation(0x1000usize as *mut u8) }) else { assert!(note_missing_u32_fixture("app/opaque_impl_callback_validate")); return; };
        unsafe { install(); RESULTS[3] = -7; assert_eq!(opaque_impl_callback_validate(owner), -7); assert_eq!(CALLS, [1, 1, 1, 1, 0]); }
    }

    #[test]
    fn first_nonzero_describes_and_tests_string() {
        let _guard = OPS_LOCK.lock();
        let Some(owner) = (unsafe { owner_with_implementation(0x1000usize as *mut u8) }) else { assert!(note_missing_u32_fixture("app/opaque_impl_callback_validate")); return; };
        unsafe { install(); RESULTS[0] = 1; DESCRIBE_NONEMPTY = true; assert_eq!(opaque_impl_callback_validate(owner), 1); assert_eq!(CALLS, [1, 0, 0, 0, 1]); }
    }

    #[test]
    fn later_predicate_short_circuits_to_empty_description() {
        let _guard = OPS_LOCK.lock();
        let Some(owner) = (unsafe { owner_with_implementation(0x1000usize as *mut u8) }) else { assert!(note_missing_u32_fixture("app/opaque_impl_callback_validate")); return; };
        unsafe { install(); RESULTS[1] = 4; assert_eq!(opaque_impl_callback_validate(owner), 0); assert_eq!(CALLS, [1, 1, 0, 0, 1]); }
    }
}
