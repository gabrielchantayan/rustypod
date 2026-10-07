//! Default interface-root local-static accessor, `FUN_0814a030` @ 0x0814a030.
//! True extent: 92 bytes (72 code + 20 literal bytes), ending at the next
//! real function, 0x0814a08c. Raw words verify four outbound plain BLs and
//! two inbound plain BLs (0x0814a194, 0x08296ef0), no predicated BLs.
//!
//! Test guard bit zero at 0x089cb1f4; if ADS acquisition succeeds, construct
//! fixed root 0x08a778f4, register the constructor result with destructor
//! word 0x0828c580 and DSO 0x089ca09c, then release. Always return the fixed
//! root, not the constructor result. Constructor 0x082973bc remains unported.
//! Deliberate deviation: hosts retain the registry's existing born-published
//! root model; isolated tests exercise the initialization algorithm with
//! local objects and callbacks instead of executing firmware addresses.
//! ARM match review: 18 original instructions versus 41 reported Rust lines
//! (including literals). LLVM inlines shutdown registration, retains both
//! guard gates, calls the constructor via BLX, and dispatches guard release.

use core::ffi::c_void;
use crate::app::facade_registry_walk::RegistryNode;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::ShutdownHandlerFn;
#[cfg(target_os = "none")]
use crate::runtime::shutdown_chain::cxa_atexit;

type Constructor = unsafe extern "C" fn(*mut RegistryNode) -> *mut RegistryNode;
type Register = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type Release = unsafe extern "C" fn(*mut u32);

// Volatile dispatch preserves the release boundary despite its empty body.
#[cfg(target_os = "none")]
static mut GUARD_RELEASE: Release = cxa_guard_release;

#[inline(always)]
unsafe fn initialize_root(
    guard: *mut u32,
    root: *mut RegistryNode,
    construct: Constructor,
    destructor: ShutdownHandlerFn,
    register: Register,
    release: Release,
) -> *mut RegistryNode {
    if core::ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        let constructed = construct(root);
        register(constructed.cast(), destructor, 0x089c_a09c);
        release(guard);
    }
    root
}

/// Returns the default interface root; see the module header for raw extent,
/// verified call census, guard protocol, and deliberate host deviation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn default_interface_root_get() -> *mut RegistryNode {
    #[cfg(target_os = "none")]
    {
        initialize_root(
            0x089c_b1f4 as *mut u32,
            0x08a7_78f4 as *mut RegistryNode,
            core::mem::transmute::<usize, Constructor>(0x0829_73bc),
            core::mem::transmute::<usize, ShutdownHandlerFn>(0x0828_c580),
            cxa_atexit,
            core::ptr::read_volatile(core::ptr::addr_of!(GUARD_RELEASE)),
        )
    }
    #[cfg(not(target_os = "none"))]
    { crate::app::facade_registry_walk::host_default_root() }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn construct(root: *mut RegistryNode) -> *mut RegistryNode {
        // Return a distinct valid address: registration must not use root.
        (*root).state_19 = 7;
        core::ptr::addr_of_mut!((*root).opaque_0c).cast()
    }
    unsafe extern "C" fn destructor(_: *mut c_void) { panic!("not invoked during initialization") }
    unsafe extern "C" fn register(result: *mut c_void, handler: ShutdownHandlerFn, dso: i32) -> i32 {
        let root = (result as *mut u8).sub(core::mem::offset_of!(RegistryNode, opaque_0c)) as *mut RegistryNode;
        assert_eq!((*root).state_19, 7);
        assert_eq!(handler as usize, destructor as *const () as usize);
        assert_eq!(dso, 0x089c_a09c);
        (*root).state_19 = 8;
        -1 // Registration failure does not suppress guard release.
    }
    unsafe extern "C" fn release(guard: *mut u32) {
        assert_eq!(*guard, 1);
        *guard = 3;
        cxa_guard_release(guard);
    }

    #[test]
    fn initialization_registers_constructor_result_and_ignores_registration_failure() {
        let mut root: RegistryNode = unsafe { core::mem::zeroed() };
        let mut guard = 0;
        let result = unsafe { initialize_root(&mut guard, &mut root, construct, destructor, register, release) };
        assert_eq!(result, core::ptr::addr_of_mut!(root));
        assert_eq!(root.state_19, 8);
        assert_eq!(guard, 3);
        // A subsequent access must not reinitialize or register again.
        root.state_19 = 9;
        unsafe { initialize_root(&mut guard, &mut root, construct, destructor, register, release); }
        assert_eq!(root.state_19, 9);
        assert_eq!(guard, 3);
    }

    #[test]
    fn nonzero_guards_skip_initialization_even_when_bit_zero_is_clear() {
        for mut guard in [1, 2, 0x8000_0000, u32::MAX] {
            let original = guard;
            let mut root: RegistryNode = unsafe { core::mem::zeroed() };
            let result = unsafe { initialize_root(&mut guard, &mut root, construct, destructor, register, release) };
            assert_eq!(result, core::ptr::addr_of_mut!(root));
            assert_eq!(root.state_19, 0);
            assert_eq!(guard, original);
        }
    }
}
