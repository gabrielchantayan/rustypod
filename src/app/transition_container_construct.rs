//! `transition_container_construct` — original: `FUN_08149cec` @ 0x08149cec.
//!
//! **True extent: 92 bytes** — 88 instruction bytes at
//! `0x08149cec..0x08149d40`, followed by the four-byte literal pool word
//! `0x0898665c` at `0x08149d44`; the next function begins at `0x08149d48`.
//! Raw branch decoding finds five inbound direct calls, all unconditional
//! `bl` (0x081030a4, 0x0811d768, 0x0818bd40, 0x081d6458, 0x0825c9b4), and
//! no predicated forms. The body constructs the unknown base with the fifth
//! argument, plants the literal word at its returned address, allocates a
//! 0x54-byte Silver-controller transition addon, constructs it with
//! `(source, flag, base_hint, 0x400, 1, 0)`, stores it at `base + 0x30`, and
//! returns that base address.
//!
//! Deliberate deviation: base constructor 0x0816bfe4 remains unported and
//! crosses a documented seam. Its identity is not inferred; the default
//! returns its supplied storage unchanged, so this function is not hook-ready
//! until that constructor is ported and wired.

#[cfg(not(test))]
use crate::cxx::transition_addon::{
    silver_controller_transition_addon_construct,
    silver_controller_transition_addon_construct_from_cstr,
};
#[cfg(not(test))]
use crate::heap::veneers::operator_new;
use core::ptr;

#[cfg(test)]
use core::sync::atomic::{AtomicUsize, Ordering};

const TRANSITION_CONTAINER_LITERAL: u32 = 0x0898_665c;
const TRANSITION_ADDON_SIZE: usize = 0x54;
const TRANSITION_ADDON_OFFSET: usize = 0x30;

/// ABI of the unported `FUN_0816bfe4` base constructor.
pub type TransitionContainerBaseConstruct = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

unsafe extern "C" fn unchanged_transition_container_base(this: *mut u8, _kind: u32) -> *mut u8 {
    this
}

/// Replacement boundary for the unidentified base constructor at 0x0816bfe4.
///
/// Its default preserves the only return-value behavior verified at this call
/// site; it does not reproduce the unported constructor's field initialization.
pub static mut TRANSITION_CONTAINER_BASE_CONSTRUCT: TransitionContainerBaseConstruct =
    unchanged_transition_container_base;

#[inline(always)]
unsafe fn transition_container_base_construct_op() -> TransitionContainerBaseConstruct {
    unsafe { ptr::read_volatile(ptr::addr_of!(TRANSITION_CONTAINER_BASE_CONSTRUCT)) }
}

#[cfg(not(test))]
#[inline(always)]
unsafe fn construct_transition_addon(
    storage: *mut u8, source: *const u8, flag: u32, base_hint: u32,
) -> *mut u8 {
    unsafe { silver_controller_transition_addon_construct(storage, source, flag, base_hint, 0x400, 1, 0) }
}

#[cfg(test)]
type TransitionAddonConstruct = unsafe extern "C" fn(*mut u8, *const u8, u32, u32, u32, u32, u32) -> *mut u8;

#[cfg(test)]
unsafe extern "C" fn test_transition_addon_construct(
    storage: *mut u8, _source: *const u8, _flag: u32, _base_hint: u32,
    _quantum: u32, _scale: u32, _context: u32,
) -> *mut u8 {
    storage
}

#[cfg(test)]
static mut TRANSITION_ADDON_CONSTRUCT: TransitionAddonConstruct = test_transition_addon_construct;

#[cfg(test)]
#[inline(always)]
unsafe fn construct_transition_addon(
    storage: *mut u8, source: *const u8, flag: u32, base_hint: u32,
) -> *mut u8 {
    unsafe {
        ptr::read_volatile(ptr::addr_of!(TRANSITION_ADDON_CONSTRUCT))(
            storage, source, flag, base_hint, 0x400, 1, 0,
        )
    }
}

#[cfg(not(test))]
#[inline(always)]
unsafe fn construct_transition_addon_from_cstr(
    storage: *mut u8, source: *const u8, flag: u32, base_hint: u32,
) -> *mut u8 {
    unsafe {
        silver_controller_transition_addon_construct_from_cstr(
            storage, source, flag, base_hint, 0x400, 1, 0,
        )
    }
}

#[cfg(test)]
static CSTR_ADDON_ARGS: [AtomicUsize; 4] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

#[cfg(test)]
#[inline(always)]
unsafe fn construct_transition_addon_from_cstr(
    storage: *mut u8, source: *const u8, flag: u32, base_hint: u32,
) -> *mut u8 {
    CSTR_ADDON_ARGS[0].store(storage as usize, Ordering::SeqCst);
    CSTR_ADDON_ARGS[1].store(source as usize, Ordering::SeqCst);
    CSTR_ADDON_ARGS[2].store(flag as usize, Ordering::SeqCst);
    CSTR_ADDON_ARGS[3].store(base_hint as usize, Ordering::SeqCst);
    0x1234_5678usize as *mut u8
}
#[cfg(not(test))]
#[inline(always)]
unsafe fn allocate_transition_addon() -> *mut u8 {
    unsafe { operator_new(TRANSITION_ADDON_SIZE) }
}

#[cfg(test)]
#[inline(always)]
unsafe fn allocate_transition_addon() -> *mut u8 {
    1usize as *mut u8
}

/// Constructs a transition container and its embedded Silver-controller
/// transition addon.
///
/// `this` must be valid for the unported base constructor and its returned
/// pointer must be writable at offsets +0 and +0x30. Neither allocation nor
/// constructor result is NULL-checked, exactly as retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn transition_container_construct(
    this: *mut u8,
    source: *const u8,
    flag: u32,
    base_hint: u32,
    kind: u32,
) -> *mut u8 {
    let base = unsafe { transition_container_base_construct_op()(this, kind) };
    unsafe {
        ptr::write_volatile(base.cast::<u32>(), TRANSITION_CONTAINER_LITERAL);
        let addon = construct_transition_addon(
            allocate_transition_addon(), source, flag, base_hint,
        );
        ptr::write_volatile(base.add(TRANSITION_ADDON_OFFSET).cast::<u32>(), addon as usize as u32);
    }
    base
}

/// `transition_container_construct_from_cstr` — original: `FUN_08149c90`
/// @ 0x08149c90.
///
/// **True extent: 92 bytes** — 88 executable bytes at
/// `0x08149c90..0x08149ce4`, followed by the four-byte literal-pool word
/// `0x0898665c` at `0x08149ce8`; the next real function begins at
/// `0x08149cec`. Raw A32 decoding finds **3 plain unconditional `bl` calls**
/// (base constructor 0x0816bfe4, `operator_new`, and the from-C-string
/// transition-addon constructor 0x08278dc4), with **0 predicated direct
/// `bl` calls**. It builds the base from its fifth argument, installs the
/// derived vtable, allocates 0x54 bytes, constructs the C-string overload
/// with `(source, flag, base_hint, 0x400, 1, 0)`, stores the result at +0x30,
/// and returns the base pointer.
///
/// # Deliberate deviation
///
/// Base constructor 0x0816bfe4 remains behind
/// [`TRANSITION_CONTAINER_BASE_CONSTRUCT`]; its default returns the supplied
/// storage unchanged, so this export is not hook-ready until that constructor
/// is ported and wired.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn transition_container_construct_from_cstr(
    this: *mut u8,
    source: *const u8,
    flag: u32,
    base_hint: u32,
    kind: u32,
) -> *mut u8 {
    let base = unsafe { transition_container_base_construct_op()(this, kind) };
    unsafe {
        ptr::write_volatile(base.cast::<u32>(), TRANSITION_CONTAINER_LITERAL);
        let addon = construct_transition_addon_from_cstr(
            allocate_transition_addon(), source, flag, base_hint,
        );
        ptr::write_volatile(base.add(TRANSITION_ADDON_OFFSET).cast::<u32>(), addon as usize as u32);
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static BASE_STORAGE: AtomicUsize = AtomicUsize::new(0);
    static BASE_KIND: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn shifted_base_construct(this: *mut u8, kind: u32) -> *mut u8 {
        BASE_STORAGE.store(this as usize, Ordering::SeqCst);
        BASE_KIND.store(kind as usize, Ordering::SeqCst);
        unsafe { this.add(4) }
    }

    unsafe extern "C" fn fixed_addon_construct(
        _storage: *mut u8, _source: *const u8, _flag: u32, _base_hint: u32,
        quantum: u32, scale: u32, context: u32,
    ) -> *mut u8 {
        assert_eq!((quantum, scale, context), (0x400, 1, 0));
        0x1234_5678usize as *mut u8
    }

    #[test]
    fn constructs_addon_at_returned_base_offset() {
        let original_base = unsafe { TRANSITION_CONTAINER_BASE_CONSTRUCT };
        let original_addon = unsafe { TRANSITION_ADDON_CONSTRUCT };
        unsafe {
            TRANSITION_CONTAINER_BASE_CONSTRUCT = shifted_base_construct;
            TRANSITION_ADDON_CONSTRUCT = fixed_addon_construct;
        };
        let mut storage = [0xa5u8; 0x40];
        let result = unsafe {
            transition_container_construct(storage.as_mut_ptr(), b"x\0".as_ptr(), 1, 0x1234, 0x8000)
        };
        unsafe {
            TRANSITION_CONTAINER_BASE_CONSTRUCT = original_base;
            TRANSITION_ADDON_CONSTRUCT = original_addon;
        };

        assert_eq!(BASE_STORAGE.load(Ordering::SeqCst), storage.as_mut_ptr() as usize);
        assert_eq!(BASE_KIND.load(Ordering::SeqCst), 0x8000);
        assert_eq!(unsafe { result.cast::<u32>().read_volatile() }, TRANSITION_CONTAINER_LITERAL);
        assert_eq!(unsafe { result.add(TRANSITION_ADDON_OFFSET).cast::<u32>().read_volatile() }, 0x1234_5678);
    }

    #[test]
    fn cstr_constructor_passes_arguments_and_installs_addon_at_offset() {
        let mut storage = [0xa5u8; 0x40];
        let source = b"transition\0";
        let result = unsafe {
            transition_container_construct_from_cstr(
                storage.as_mut_ptr(), source.as_ptr(), 1, 0xfeed_beef, 0x8000,
            )
        };

        assert_eq!(result, storage.as_mut_ptr());
        assert_eq!(CSTR_ADDON_ARGS[0].load(Ordering::SeqCst), 1);
        assert_eq!(CSTR_ADDON_ARGS[1].load(Ordering::SeqCst), source.as_ptr() as usize);
        assert_eq!(CSTR_ADDON_ARGS[2].load(Ordering::SeqCst), 1);
        assert_eq!(CSTR_ADDON_ARGS[3].load(Ordering::SeqCst), 0xfeed_beef);
        assert_eq!(unsafe { result.cast::<u32>().read_volatile() }, TRANSITION_CONTAINER_LITERAL);
        assert_eq!(
            unsafe { result.add(TRANSITION_ADDON_OFFSET).cast::<u32>().read_volatile() },
            0x1234_5678
        );
    }
}
