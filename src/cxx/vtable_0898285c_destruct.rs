//! `vtable_0898285c_destruct` — retailOS `FUN_0839c964` @ `0x0839c964`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes nine ARM words: eight instruction words from
//! `0x0839c964` through the tail `b` at `0x0839c984`, followed by the vtable
//! literal `0x0898285c` at `0x0839c988`; `0x0839c98c` starts the next real
//! function. The true size is **36 bytes**. Its body has one plain `bl` to
//! [`string_object_opaque_base_destroy`] (`0x0839c8b0`) and a tail `b` to
//! [`registry_container_destruct`] (`0x08135380`). Decoding every ARM B/BL
//! word finds two inbound plain `bl` sites (`0x0811da00`, `0x08284a98`) and
//! no predicated `bl` sites.
//!
//! ## Algorithm
//!
//! Install the derived destruction vtable, destroy the leading opaque string
//! object, then tail-chain into the registry-container destructor. The class
//! identity is not established, so the name describes the verified vtable
//! destructor role. Deliberate deviation: host tests replace the final direct
//! tail call because `Registry` has host-width pointer fields, while stock
//! passes the target-layout object unchanged.

#[cfg(not(test))]
use crate::app::class_registry::registry_container_destruct;
use crate::app::registry::Registry;
use crate::cxx::string_object::StringObject;
use crate::cxx::string_object_opaque_base_destroy::string_object_opaque_base_destroy;

const VTABLE_WORD: u32 = 0x0898_285c;

#[cfg(test)]
unsafe extern "C" fn host_registry_container_destruct(this: *mut Registry) -> *mut Registry {
    this
}

/// Host-only substitute for the direct tail branch to
/// [`registry_container_destruct`].
#[cfg(test)]
static mut REGISTRY_CONTAINER_DESTRUCT: unsafe extern "C" fn(*mut Registry) -> *mut Registry =
    host_registry_container_destruct;

/// Installs the destruction vtable, destroys its string-object base, and
/// tail-chains into the registry-container destructor.
///
/// Original: `FUN_0839c964` @ `0x0839c964` (36 bytes; two plain inbound `bl`
/// sites, no predicated inbound `bl` sites).
///
/// # Safety
///
/// `this` must point to a writable target-layout object accepted by both
/// destructors. No NULL guard exists in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_0898285c_destruct(this: *mut StringObject) -> *mut StringObject {
    unsafe {
        this.cast::<u32>().write_volatile(VTABLE_WORD);
        let this = string_object_opaque_base_destroy(this);

        #[cfg(test)]
        {
            let destruct = core::ptr::read_volatile(core::ptr::addr_of!(REGISTRY_CONTAINER_DESTRUCT));
            return destruct(this.cast::<Registry>()).cast::<StringObject>();
        }

        #[cfg(not(test))]
        registry_container_destruct(this.cast::<Registry>()).cast::<StringObject>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static SEEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_registry_destruct(this: *mut Registry) -> *mut Registry {
        SEEN.store(this as usize, Ordering::SeqCst);
        this
    }

    #[test]
    fn destroys_string_base_then_tail_chains_with_original_pointer() {
        let _lock = LOCK.lock();
        let old = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(REGISTRY_CONTAINER_DESTRUCT))
        };
        unsafe {
            core::ptr::addr_of_mut!(REGISTRY_CONTAINER_DESTRUCT).write(record_registry_destruct);
        }
        let mut object = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        SEEN.store(0, Ordering::SeqCst);

        let result = unsafe { vtable_0898285c_destruct(&mut object) };

        assert_eq!(result as *mut StringObject, &mut object as *mut StringObject);
        assert_eq!(SEEN.load(Ordering::SeqCst), (&mut object as *mut StringObject) as usize);
        assert_ne!(object.vtable, core::ptr::null());
        unsafe { core::ptr::addr_of_mut!(REGISTRY_CONTAINER_DESTRUCT).write(old); }
    }
}
