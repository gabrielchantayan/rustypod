//! Attached-element observable-array destructor — `FUN_083d129c` @ `0x083d129c`.
//!
//! Raw `osos.dec` establishes 60 bytes: fourteen A32 instructions through
//! the tail B at `0x083d12d0`, then vtable literal `0x089a4c20` at
//! `0x083d12d4`. The next function begins with PUSH at `0x083d12d8`.
//! Whole-image aligned ARM decoding finds one inbound plain BL (`0x0826b610`)
//! and no predicated BL callers. The body has one plain BL to the ported
//! element-release helper, one indirect BLXNE, and one tail B to the base.
//!
//! Plants the derived vtable, releases a non-NULL attached object at +0x14
//! through its vtable slot +0x1c, releases enabled elements through
//! `observable_array_release_elements_083d119c`, then destroys the base array.
//! The deleting caller uses the returned `this` for operator delete.
//! Deliberate deviations: Rust models BLXNE and the tail B as ordinary calls;
//! host builds replace target-width virtual dispatch and the element helper
//! (whose native host layout differs) with explicit seams. ARM calls the
//! existing Rust helper directly; no unidentified callee identity is assumed.

const DERIVED_VTABLE: u32 = 0x089a_4c20;
const ATTACHED_WORD: usize = 0x14 / 4;
type ReleaseAttached = unsafe extern "C" fn(*mut u8);
type ReleaseElements = unsafe extern "C" fn(*mut u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_attached(_: *mut u8) {
    panic!("install attached-element destructor host seams")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_elements(_: *mut u32) {
    panic!("install attached-element destructor host seams")
}

/// Host-only replacements for target-layout dispatch. Serialize installation.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ATTACHED_RELEASE_ELEMENTS_DESTRUCT_OPS: (ReleaseElements, ReleaseAttached) =
    (missing_elements, missing_attached);

/// Releases attached state and elements, destroys the base, and returns `this`.
///
/// # Safety
/// `this` must name writable, aligned target-layout storage through +0x17.
/// Its attached object and enabled element cells must support the verified
/// virtual methods. The existing element-release and base-destructor safety
/// contracts also apply. Host callers must install the host seams.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_attached_release_elements_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(DERIVED_VTABLE);
        let attached = this.add(ATTACHED_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                let vtable = attached.cast::<u32>().read_volatile() as usize as *const u32;
                let release: ReleaseAttached = core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize);
                release(attached);
            }
            super::observable_array_release_elements_083d119c::observable_array_release_elements_083d119c(this.cast());
        }
        #[cfg(not(target_os = "none"))]
        {
            let (elements, release) = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_ELEMENTS_DESTRUCT_OPS));
            if !attached.is_null() {
                release(attached);
            }
            elements(this);
        }
        super::observable_array::observable_array_destruct(this.cast()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    static THIS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn release(attached: *mut u8) {
        let this = THIS.load(Ordering::SeqCst) as *mut u32;
        unsafe { assert_eq!(this.read(), DERIVED_VTABLE); }
        RELEASED.store(attached as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn elements(this: *mut u32) {
        unsafe {
            assert_eq!(this as usize, THIS.load(Ordering::SeqCst));
            assert_eq!(this.read(), DERIVED_VTABLE);
            assert_eq!(RELEASED.load(Ordering::SeqCst), this.add(ATTACHED_WORD).read() as usize);
            assert_eq!(this.add(1).read(), 3); // base cleanup must happen later
            this.add(4).write(0x55); // element cleanup's effects survive the base
        }
    }

    #[test]
    fn optional_attached_release_precedes_elements_and_base_cleanup() {
        let _lock = LOCK.lock();
        unsafe {
            let old = core::ptr::read(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_ELEMENTS_DESTRUCT_OPS));
            core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_ELEMENTS_DESTRUCT_OPS).write((elements, release));
            for attached in [0, 0x1234_5000] {
                let mut object = [0xfeed_face, 3, 0, 0, 1, attached];
                THIS.store(object.as_mut_ptr() as usize, Ordering::SeqCst);
                RELEASED.store(0, Ordering::SeqCst);
                let result = observable_array_attached_release_elements_destruct(object.as_mut_ptr());
                assert_eq!(result, object.as_mut_ptr());
                assert_eq!(object, [super::super::observable_array::OBSERVABLE_ARRAY_VTABLE, 0, 0, 0, 0x55, attached]);
                assert_eq!(RELEASED.load(Ordering::SeqCst), attached as usize);
            }
            core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_ELEMENTS_DESTRUCT_OPS).write(old);
        }
    }
}
