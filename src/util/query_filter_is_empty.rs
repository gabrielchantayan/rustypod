//! Filtered query emptiness — `FUN_08229824` @ **0x08229824**.
//! True extent: **148 bytes**, including the literal at 0x082298b4;
//! next entry 0x082298b8. Raw words verify one plain BL, zero predicated
//! BLs, five plain BLXs and one BLXNE. Two inbound BLs, both plain.
//!
//! Creates a mode-zero query, dispatches +0x38 and +0xec, supplies
//! (0x80, 0x00200004) to +0x5c, supplies zero to +0x100, and tests
//! the +0x108 result for zero. Dispatches +0x1c to release the object
//! after saving that predicate. Virtual targets remain unresolved runtime
//! methods; no callee identities or meanings for their flags are assumed.
//!
//! Deviations: native-width host vtables retain target word indices;
//! host builds expose only the factory substitution used by tests.
//! The ignored incoming r0 is omitted from the Rust signature.

//! ARM codegen removes the redundant release NULL check after unchecked
//! dispatches and uses CLZ/LSR for the saved zero predicate.
use crate::util::inner_state::query_object_create;

type CreateQuery = unsafe extern "C" fn(u32) -> *mut u8;
type QueryMethod = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub static mut QUERY_FILTER_CREATE: CreateQuery = query_object_create;

unsafe fn entry(query: *mut u8, offset: usize) -> usize {
    let vtable = (query as *const *const usize).read();
    vtable.add(offset / 4).read()
}

unsafe fn evaluate(create: CreateQuery) -> u32 {
    let query = create(0);
    let first: QueryMethod = core::mem::transmute(entry(query, 0x38));
    first(query);
    let second: QueryMethod = core::mem::transmute(entry(query, 0xec));
    second(query);
    let filter: unsafe extern "C" fn(*mut u8, u32, u32) =
        core::mem::transmute(entry(query, 0x5c));
    filter(query, 0x80, 0x0020_0004);
    let option: unsafe extern "C" fn(*mut u8, u32) =
        core::mem::transmute(entry(query, 0x100));
    option(query, 0);
    let result: unsafe extern "C" fn(*mut u8) -> u32 =
        core::mem::transmute(entry(query, 0x108));
    let empty = (result(query) == 0) as u32;
    if !query.is_null() {
        let release: QueryMethod = core::mem::transmute(entry(query, 0x1c));
        release(query);
    }
    empty
}

/// Return 1 exactly when the configured query's result is zero.
///
/// # Safety
/// The factory must return a non-null object with callable vtable entries
/// +0x38, +0xec, +0x5c, +0x100, +0x108 and +0x1c. Earlier methods may
/// replace its vtable; every subsequent dispatch reloads it, as in stock.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn query_filter_is_empty() -> u32 {
    #[cfg(target_os = "none")]
    return evaluate(query_object_create);
    #[cfg(not(target_os = "none"))]
    evaluate(core::ptr::read_volatile(core::ptr::addr_of!(QUERY_FILTER_CREATE)))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut OBJECT: *mut Fixture = core::ptr::null_mut();

    #[repr(C)]
    struct Fixture {
        vtable: *const usize,
        replacement: *const usize,
        phase: u32,
        result: u32,
        released: bool,
    }

    unsafe extern "C" fn create(mode: u32) -> *mut u8 {
        assert_eq!(mode, 0);
        OBJECT.cast()
    }
    unsafe extern "C" fn begin(query: *mut u8) {
        let object = &mut *query.cast::<Fixture>();
        assert_eq!(object.phase, 0);
        object.phase = 1;
        object.vtable = object.replacement;
    }
    unsafe extern "C" fn prepare(query: *mut u8) {
        let object = &mut *query.cast::<Fixture>();
        assert_eq!(object.phase, 1);
        object.phase = 2;
    }
    unsafe extern "C" fn filter(query: *mut u8, flags: u32, field: u32) {
        let object = &mut *query.cast::<Fixture>();
        assert_eq!((object.phase, flags, field), (2, 0x80, 0x0020_0004));
        object.phase = 3;
    }
    unsafe extern "C" fn option(query: *mut u8, value: u32) {
        let object = &mut *query.cast::<Fixture>();
        assert_eq!((object.phase, value), (3, 0));
        object.phase = 4;
    }
    unsafe extern "C" fn result(query: *mut u8) -> u32 {
        let object = &mut *query.cast::<Fixture>();
        assert_eq!(object.phase, 4);
        object.phase = 5;
        object.result
    }
    unsafe extern "C" fn release(query: *mut u8) {
        let object = &mut *query.cast::<Fixture>();
        assert_eq!(object.phase, 5);
        object.released = true;
        object.result = !object.result;
        object.phase = 6;
    }

    #[test]
    fn zero_predicate_survives_release_and_vtable_replacement() {
        let _guard = LOCK.lock();
        let mut initial = [0usize; 0x10c / 4];
        initial[0x38 / 4] = begin as *const () as usize;
        let mut replacement = [0usize; 0x10c / 4];
        replacement[0xec / 4] = prepare as *const () as usize;
        replacement[0x5c / 4] = filter as *const () as usize;
        replacement[0x100 / 4] = option as *const () as usize;
        replacement[0x108 / 4] = result as *const () as usize;
        replacement[0x1c / 4] = release as *const () as usize;
        unsafe {
            let previous = QUERY_FILTER_CREATE;
            QUERY_FILTER_CREATE = create;
            for value in [0, 1, 0x8000_0000, u32::MAX] {
                let mut object = Fixture {
                    vtable: initial.as_ptr(), replacement: replacement.as_ptr(),
                    phase: 0, result: value, released: false,
                };
                OBJECT = &mut object;
                assert_eq!(query_filter_is_empty(), (value == 0) as u32);
                assert!(object.released);
                assert_eq!(object.phase, 6);
                assert_eq!(object.result, !value);
            }
            QUERY_FILTER_CREATE = previous;
            OBJECT = core::ptr::null_mut();
        }
    }
}
