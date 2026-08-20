//! `resource_cache_refresh_get` — original: `FUN_08047020` @ 0x08047020
//! (60 bytes: 56 bytes of code plus the callback literal at 0x0804705c).
//!
//! # Algorithm
//!
//! The object owns a resource-callback root at `+0x40` and a three-field
//! cache at `+0x618`: a dirty byte, an auxiliary word, and the returned value.
//! A nonzero dirty byte or `force_refresh` clears all three fields, then calls
//! the unported resource-callback dispatcher `FUN_0806b604(root, 0x080db63c,
//! object)`. The dispatcher callback repopulates the cache; its status return
//! is ignored. A clean, unforced call skips dispatch and returns the existing
//! `+0x620` word.
//!
//! The callback literal enters an allocation-handler tail at 0x080db63c and
//! relies on `FUN_0806b604` preserving its third argument in `r2` and root in
//! `r4`; it is therefore not a normal Rust-callable function pointer. The
//! unported dispatcher is represented by [`RESOURCE_CACHE_CALLBACK_DISPATCH`]
//! so firmware integration can wire the exact contract and host tests can
//! observe it without inventing the callback's behavior.

/// Offset of the resource callback root word in the owning object.
const RESOURCE_CALLBACK_ROOT_OFFSET: usize = 0x40;
/// Offset of the invalid/dirty cache byte.
const CACHE_DIRTY_OFFSET: usize = 0x618;
/// Offset of the cache's auxiliary word.
const CACHE_AUXILIARY_OFFSET: usize = 0x61c;
/// Offset of the cached result word returned by this getter.
const CACHE_VALUE_OFFSET: usize = 0x620;
/// The callback literal loaded from 0x0804705c.
pub const RESOURCE_CACHE_REFRESH_CALLBACK: usize = 0x080d_b63c;

/// ABI of the unported `FUN_0806b604` resource callback dispatcher.
///
/// `callback` is the raw ARM entry address, not a Rust function pointer: this
/// particular entry depends on registers that `FUN_0806b604` preserves across
/// its indirect call. The status result is deliberately ignored by
/// [`resource_cache_refresh_get`].
pub type ResourceCacheCallbackDispatch = unsafe extern "C" fn(
    resource_callback_root: *mut u8,
    callback: usize,
    context: *mut u8,
) -> i32;

unsafe extern "C" fn missing_resource_cache_callback_dispatch(
    _resource_callback_root: *mut u8,
    _callback: usize,
    _context: *mut u8,
) -> i32 {
    // The unported dispatcher has no sound stand-in: returning would pretend
    // the cache was refreshed. Wiring it is required for target integration.
    loop {
        core::hint::spin_loop();
    }
}

/// Seam for the unported resource-callback dispatcher `FUN_0806b604`.
///
/// The default deliberately does not fabricate a refreshed cache. Firmware
/// integration installs the retail dispatcher contract; host tests install a
/// recorder through `core::ptr::addr_of_mut!`.
pub static mut RESOURCE_CACHE_CALLBACK_DISPATCH: ResourceCacheCallbackDispatch =
    missing_resource_cache_callback_dispatch;

#[inline(always)]
unsafe fn resource_cache_callback_dispatch() -> ResourceCacheCallbackDispatch {
    core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_CACHE_CALLBACK_DISPATCH))
}

/// resource_cache_refresh_get — original: `FUN_08047020` @ 0x08047020
/// (60 bytes: 56 bytes of code plus the callback literal at 0x0804705c).
///
/// Returns the object's `+0x620` cache word. A refresh happens exactly when
/// the `+0x618` dirty byte is nonzero **or** `force_refresh` is nonzero. The
/// refresh clears the dirty byte and both cache words before invoking
/// `FUN_0806b604(root, 0x080db63c, object)`, then returns whatever word the
/// callback left at `+0x620`; the dispatcher's own return value is ignored.
///
/// # Safety
///
/// `object` must be non-NULL, four-byte aligned, and point to a writable
/// object carrying the raw fields above. The retail ARM has no null or
/// alignment guards; invalid input faults there rather than producing an
/// error result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_cache_refresh_get(
    object: *mut u8,
    force_refresh: u32,
) -> u32 {
    if object.add(CACHE_DIRTY_OFFSET).read_volatile() != 0 || force_refresh != 0 {
        object.add(CACHE_DIRTY_OFFSET).write_volatile(0);
        object
            .add(CACHE_AUXILIARY_OFFSET)
            .cast::<u32>()
            .write_volatile(0);
        object
            .add(CACHE_VALUE_OFFSET)
            .cast::<u32>()
            .write_volatile(0);

        let resource_callback_root = object
            .add(RESOURCE_CALLBACK_ROOT_OFFSET)
            .cast::<*mut u8>()
            .read_volatile();
        resource_cache_callback_dispatch()(resource_callback_root, RESOURCE_CACHE_REFRESH_CALLBACK, object);
    }

    object.add(CACHE_VALUE_OFFSET).cast::<u32>().read_volatile()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    const CACHE_OBJECT_SIZE: usize = CACHE_VALUE_OFFSET + core::mem::size_of::<u32>();

    #[repr(align(8))]
    struct CacheObject([u8; CACHE_OBJECT_SIZE]);

    impl CacheObject {
        fn new() -> Self {
            CacheObject([0; CACHE_OBJECT_SIZE])
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }

        unsafe fn set_root(&mut self, root: *mut u8) {
            self.ptr()
                .add(RESOURCE_CALLBACK_ROOT_OFFSET)
                .cast::<*mut u8>()
                .write_volatile(root);
        }

        unsafe fn set_dirty(&mut self, dirty: u8) {
            self.ptr().add(CACHE_DIRTY_OFFSET).write_volatile(dirty);
        }

        unsafe fn set_auxiliary(&mut self, value: u32) {
            self.ptr()
                .add(CACHE_AUXILIARY_OFFSET)
                .cast::<u32>()
                .write_volatile(value);
        }

        unsafe fn set_value(&mut self, value: u32) {
            self.ptr()
                .add(CACHE_VALUE_OFFSET)
                .cast::<u32>()
                .write_volatile(value);
        }

        unsafe fn dirty(&mut self) -> u8 {
            self.ptr().add(CACHE_DIRTY_OFFSET).read_volatile()
        }

        unsafe fn auxiliary(&mut self) -> u32 {
            self.ptr()
                .add(CACHE_AUXILIARY_OFFSET)
                .cast::<u32>()
                .read_volatile()
        }
    }

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: usize = 0;
    static mut DISPATCH_ROOT: *mut u8 = core::ptr::null_mut();
    static mut DISPATCH_CALLBACK: usize = 0;
    static mut DISPATCH_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut AUXILIARY_AT_DISPATCH: u32 = 0;
    static mut VALUE_AT_DISPATCH: u32 = 0;
    static mut CALLBACK_VALUE: u32 = 0;
    static mut DISPATCH_STATUS: i32 = 0;

    unsafe extern "C" fn record_refresh_dispatch(
        root: *mut u8,
        callback: usize,
        context: *mut u8,
    ) -> i32 {
        DISPATCH_CALLS += 1;
        DISPATCH_ROOT = root;
        DISPATCH_CALLBACK = callback;
        DISPATCH_CONTEXT = context;
        AUXILIARY_AT_DISPATCH = context
            .add(CACHE_AUXILIARY_OFFSET)
            .cast::<u32>()
            .read_volatile();
        VALUE_AT_DISPATCH = context
            .add(CACHE_VALUE_OFFSET)
            .cast::<u32>()
            .read_volatile();
        context
            .add(CACHE_VALUE_OFFSET)
            .cast::<u32>()
            .write_volatile(CALLBACK_VALUE);
        DISPATCH_STATUS
    }

    struct DispatchGuard(MutexGuard<'static, ()>);

    impl Drop for DispatchGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RESOURCE_CACHE_CALLBACK_DISPATCH)
                    .write_volatile(missing_resource_cache_callback_dispatch);
            }
        }
    }

    fn install_recorder(callback_value: u32, dispatch_status: i32) -> DispatchGuard {
        let guard = DISPATCH_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            DISPATCH_CALLS = 0;
            DISPATCH_ROOT = core::ptr::null_mut();
            DISPATCH_CALLBACK = 0;
            DISPATCH_CONTEXT = core::ptr::null_mut();
            AUXILIARY_AT_DISPATCH = u32::MAX;
            VALUE_AT_DISPATCH = u32::MAX;
            CALLBACK_VALUE = callback_value;
            DISPATCH_STATUS = dispatch_status;
            core::ptr::addr_of_mut!(RESOURCE_CACHE_CALLBACK_DISPATCH)
                .write_volatile(record_refresh_dispatch);
        }
        DispatchGuard(guard)
    }

    #[test]
    fn clean_unforced_cache_returns_without_dispatch_or_writes() {
        let _dispatch = install_recorder(0xffff_ffff, 0);
        let mut object = CacheObject::new();
        let root = 0x1234_5000usize as *mut u8;
        unsafe {
            object.set_root(root);
            object.set_dirty(0);
            object.set_auxiliary(0x1122_3344);
            object.set_value(0x5566_7788);
            assert_eq!(resource_cache_refresh_get(object.ptr(), 0), 0x5566_7788);
            assert_eq!(object.dirty(), 0);
            assert_eq!(object.auxiliary(), 0x1122_3344);
            assert_eq!(DISPATCH_CALLS, 0);
        }
    }

    #[test]
    fn dirty_cache_clears_before_dispatch_and_returns_callback_value() {
        let _dispatch = install_recorder(0xa1b2_c3d4, -50);
        let mut object = CacheObject::new();
        let root = 0x1234_5000usize as *mut u8;
        unsafe {
            object.set_root(root);
            object.set_dirty(0x80);
            object.set_auxiliary(0x1122_3344);
            object.set_value(0x5566_7788);

            assert_eq!(resource_cache_refresh_get(object.ptr(), 0), CALLBACK_VALUE);
            assert_eq!(object.dirty(), 0);
            assert_eq!(object.auxiliary(), 0);
            assert_eq!(DISPATCH_CALLS, 1);
            assert_eq!(DISPATCH_ROOT, root);
            assert_eq!(DISPATCH_CALLBACK, RESOURCE_CACHE_REFRESH_CALLBACK);
            assert_eq!(DISPATCH_CONTEXT, object.ptr());
            assert_eq!(AUXILIARY_AT_DISPATCH, 0);
            assert_eq!(VALUE_AT_DISPATCH, 0);
        }
    }

    #[test]
    fn nonzero_force_refreshes_a_clean_cache_and_ignores_dispatch_status() {
        let _dispatch = install_recorder(0xdec0_aded, -0x32);
        let mut object = CacheObject::new();
        unsafe {
            object.set_dirty(0);
            object.set_auxiliary(0xfedc_ba98);
            object.set_value(0x7654_3210);

            assert_eq!(resource_cache_refresh_get(object.ptr(), 0x8000_0000), CALLBACK_VALUE);
            assert_eq!(DISPATCH_CALLS, 1);
            assert_eq!(object.dirty(), 0);
            assert_eq!(object.auxiliary(), 0);
        }
    }
}
