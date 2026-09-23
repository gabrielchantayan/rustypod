//! Constructor for the 300-byte client that binds a base object to a registry
//! observer and one of the two displays.
//!
//! The parent constructor and resource lookup remain retail seams: their
//! identities are not established by the recovered code.

use core::ptr;

use crate::app::class_registry::{registry_observer_base_construct, registry_set_observer, RegistryObserver};
use crate::drivers::display::{display_get, Display};
use crate::heap::veneers::operator_new;

const CLIENT_VTABLE_ADDRESS: usize = 0x0898_c5f4;
const OBSERVER_VTABLE_ADDRESS: usize = 0x0898_9918;
const RESOURCE_KEY: u32 = 0x534c_7374;

pub type ClientBaseConstruct = unsafe extern "C" fn(
    allocation: *mut u8, arg1: *mut u8, arg2: u32, arg3: *mut u8, arg4: *mut u8, enabled: u32,
) -> *mut u8;
pub type RegistryGet = unsafe extern "C" fn() -> *mut u8;
pub type RegistryLookup = unsafe extern "C" fn(*mut u8, u32) -> u32;
pub type ObserverConstruct = unsafe extern "C" fn(*mut RegistryObserver) -> *mut RegistryObserver;
pub type ObserverInstall = unsafe extern "C" fn(*mut u8, *mut RegistryObserver) -> *mut u8;
pub type DisplayGet = unsafe extern "C" fn(u32) -> *mut Display;
pub type Allocate = unsafe extern "C" fn(usize) -> *mut u8;
unsafe extern "C" fn retail_client_base_construct(
    allocation: *mut u8, arg1: *mut u8, arg2: u32, arg3: *mut u8, arg4: *mut u8, enabled: u32,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let construct: ClientBaseConstruct = core::mem::transmute(0x0811_e478usize);
        return construct(allocation, arg1, arg2, arg3, arg4, enabled);
    }
    #[cfg(not(target_os = "none"))]
    allocation
}
unsafe extern "C" fn retail_registry_get() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let get: RegistryGet = core::mem::transmute(0x0819_fdb0usize);
        return get();
    }
    #[cfg(not(target_os = "none"))]
    core::ptr::null_mut()
}
unsafe extern "C" fn retail_registry_lookup(registry: *mut u8, key: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let lookup: RegistryLookup = core::mem::transmute(0x0811_cc00usize);
        return lookup(registry, key);
    }
    #[cfg(not(target_os = "none"))]
    0
}
unsafe extern "C" fn direct_observer_construct(observer: *mut RegistryObserver) -> *mut RegistryObserver {
    registry_observer_base_construct(observer)
}
unsafe extern "C" fn direct_observer_install(client: *mut u8, observer: *mut RegistryObserver) -> *mut u8 {
    registry_set_observer(client.cast(), observer)
}

#[derive(Clone, Copy)]
pub struct RegistryDisplayClientOps {
    pub base_construct: ClientBaseConstruct,
    pub allocate: Allocate,
    pub registry_get: RegistryGet,
    pub registry_lookup: RegistryLookup,
    pub observer_construct: ObserverConstruct,
    pub observer_install: ObserverInstall,
    pub display_get: DisplayGet,
}
const DEFAULT_OPS: RegistryDisplayClientOps = RegistryDisplayClientOps {
    base_construct: retail_client_base_construct,
    registry_get: retail_registry_get,
    registry_lookup: retail_registry_lookup,
    allocate: operator_new,
    observer_construct: direct_observer_construct,
    observer_install: direct_observer_install,
    display_get,
};
pub static mut REGISTRY_DISPLAY_CLIENT_OPS: RegistryDisplayClientOps = DEFAULT_OPS;

macro_rules! ops { ($field:ident) => { core::ptr::read_volatile(core::ptr::addr_of!(REGISTRY_DISPLAY_CLIENT_OPS.$field)) }; }

/// registry_display_client_construct — original: `FUN_081b9db8` @ 0x081b9db8
/// (196 code bytes; true extent 208 bytes, 0x081b9db8..0x081b9e88, including
/// the three-word literal pool). Exactly 3 inbound plain unconditional `bl`
/// calls and no predicated `bl` calls were verified from `osos.dec`.
///
/// Runs the unresolved parent constructor, installs the derived vtable, creates
/// and installs an 8-byte registry observer, resolves `"SLst"`, then records
/// the display selected by `on_secondary_display`. Deliberate deviation: the
/// three unported calls are replaceable operations; target builds use their
/// verified retail addresses, while the two identified constructors and the
/// display getter are called directly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_display_client_construct(
    allocation: *mut u8, arg1: *mut u8, arg2: u32, arg3: *mut u8, arg4: *mut u8, on_secondary_display: u32,
) -> *mut u8 {
    let client = ops!(base_construct)(allocation, arg1, arg2, arg3, arg4, (on_secondary_display != 0) as u32);
    ptr::write_volatile(client.cast::<u32>(), CLIENT_VTABLE_ADDRESS as u32);
    let observer = ops!(allocate)(8).cast::<RegistryObserver>();
    let observer = ops!(observer_construct)(observer);
    ptr::write_volatile(ptr::addr_of_mut!((*observer).vtable), OBSERVER_VTABLE_ADDRESS as *const _);
    ops!(observer_install)(client, observer);
    ptr::write_volatile(client.add(0x108), on_secondary_display as u8);
    ptr::write_volatile(client.add(0x109), 0);
    ptr::write_volatile(client.add(0x10c).cast::<u32>(), 0);
    ptr::write_volatile(client.add(0x110).cast::<u32>(), u32::MAX);
    let resource = ops!(registry_lookup)(ops!(registry_get)(), RESOURCE_KEY);
    ptr::write_volatile(client.add(0x118).cast::<u32>(), resource);
    ptr::write_volatile(client.add(0x114).cast::<u32>(), 0);
    ptr::write_volatile(client.add(0x11c).cast::<u32>(), 0);
    ptr::write_volatile(client.add(0x120).cast::<u32>(), 0);
    let display_id = if on_secondary_display == 0 { 0 } else { 1 };
    ptr::write_volatile(client.add(0x124).cast::<u32>(), ops!(display_get)(display_id) as usize as u32);
    ptr::write_volatile(client.add(0x128).cast::<u32>(), if on_secondary_display == 0 { u32::MAX } else { 0 });
    client
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    static mut TEST_CLIENT: *mut u8 = ptr::null_mut();
    static LOCK: Mutex<()> = Mutex::new(());
    static mut DISPLAY_ID: u32 = u32::MAX;
    unsafe extern "C" fn base(a: *mut u8, _: *mut u8, _: u32, _: *mut u8, _: *mut u8, enabled: u32) -> *mut u8 { ptr::write_volatile(a.add(0x107), enabled as u8); a }
    unsafe extern "C" fn get() -> *mut u8 { 0x1234usize as *mut u8 }
    unsafe extern "C" fn lookup(registry: *mut u8, key: u32) -> u32 { assert_eq!(registry as usize, 0x1234); assert_eq!(key, RESOURCE_KEY); 0xfeed_beef }
    unsafe extern "C" fn observer(observer: *mut RegistryObserver) -> *mut RegistryObserver { observer }
    unsafe extern "C" fn allocate(_: usize) -> *mut u8 { TEST_CLIENT.add(0x180) }
    unsafe extern "C" fn install(client: *mut u8, observer: *mut RegistryObserver) -> *mut u8 { ptr::write_volatile(client.add(0xa8).cast::<u32>(), observer as usize as u32); client }
    unsafe extern "C" fn display(id: u32) -> *mut Display { DISPLAY_ID = id; (0x8000 + id as usize) as *mut Display }
    #[test]
    fn initializes_both_display_variants_and_all_known_fields() {
        let _lock = LOCK.lock();
        let Some(client) = try_map_u32_slab(hints::REGISTRY_DISPLAY_CLIENT_CONSTRUCT, 0x200) else { return };
        unsafe {
            TEST_CLIENT = client;
            REGISTRY_DISPLAY_CLIENT_OPS = RegistryDisplayClientOps { base_construct: base, registry_get: get, registry_lookup: lookup, allocate, observer_construct: observer, observer_install: install, display_get: display };
            for enabled in [0, 1] {
                let result = registry_display_client_construct(client, ptr::null_mut(), 7, ptr::null_mut(), ptr::null_mut(), enabled);
                assert_eq!(result, client); assert_eq!(DISPLAY_ID, enabled); assert_eq!(ptr::read_volatile(client.cast::<u32>()), CLIENT_VTABLE_ADDRESS as u32);
                assert_ne!(ptr::read_volatile(client.add(0xa8).cast::<u32>()), 0); assert_eq!(ptr::read_volatile(client.add(0x108)), enabled as u8); assert_eq!(ptr::read_volatile(client.add(0x109)), 0);
                assert_eq!(ptr::read_volatile(client.add(0x10c).cast::<u32>()), 0); assert_eq!(ptr::read_volatile(client.add(0x110).cast::<u32>()), u32::MAX); assert_eq!(ptr::read_volatile(client.add(0x114).cast::<u32>()), 0); assert_eq!(ptr::read_volatile(client.add(0x118).cast::<u32>()), 0xfeed_beef); assert_eq!(ptr::read_volatile(client.add(0x11c).cast::<u32>()), 0); assert_eq!(ptr::read_volatile(client.add(0x120).cast::<u32>()), 0); assert_eq!(ptr::read_volatile(client.add(0x124).cast::<u32>()), 0x8000 + enabled); assert_eq!(ptr::read_volatile(client.add(0x128).cast::<u32>()), if enabled == 0 { u32::MAX } else { 0 });
            }
            REGISTRY_DISPLAY_CLIENT_OPS = DEFAULT_OPS;
        }
    }
}
