//! `app_screen_set_layout` — original: `FUN_0817434c` @ `0x0817434c`
//! (28 bytes; **25 direct `bl` call sites**, all unconditional, binary-scanned
//! from `work/firmware/osos.dec`).
//!
//! # Algorithm
//!
//! Assign the supplied [`StringObject`] to the screen object's embedded layout
//! name at target offset `+0x1c`, then tail-enter `FUN_081779c8` with the
//! screen object. The latter is an unported framework notification routine: it
//! dispatches virtual slot `+0x58` twice around `FUN_08177424`, forwarding the
//! final virtual call's result. The direct `bl` to the already-ported
//! `string_object_assign` and the final `b 0x081779c8` are decoded from raw
//! bytes; Ghidra incorrectly folds unrelated code into this function.
//!
//! # Deliberate deviation
//!
//! On ARM the notification remains a call to its retailOS entry. Host builds
//! use [`SCREEN_LAYOUT_ASSIGN_OPS`] because that ROM framework callback cannot
//! run natively. The normal Rust call represents the stock tail branch while
//! preserving its returned value.

#[cfg(not(target_arch = "arm"))]
use core::ptr::addr_of;

use crate::app::registry::{object_cast_to_class, registry_lookup_by_id, FrameworkObject};
use crate::app::resource_chain::{resource_chain_find_string, ResourceProvider};
use crate::app::string_owner_init::string_owner_embedded_init;
use crate::cxx::string_object::{string_object_assign, string_object_destroy, StringObject};

/// The class id `app_screen_set_layout_from_resource` downcasts the
/// registered instance to before asking it for a string (`mov r4, #5` @
/// 0x08174310). Five other image sites (0x08172b1c, 0x081805ac, 0x081851c8,
/// 0x0819ee98, 0x081dd590) cast to the same id immediately around
/// resource-chain calls, so 5 is the resource-provider interface id.
pub const RESOURCE_PROVIDER_CLASS_ID: u32 = 5;

/// ABI of the unported layout-change framework notification @ `0x081779c8`.
pub type ScreenLayoutChanged = unsafe extern "C" fn(screen: *mut u8) -> *mut u8;

/// Host-model boundary for the notification tail call.
#[derive(Clone, Copy)]
pub struct ScreenLayoutAssignOps {
    pub layout_changed: ScreenLayoutChanged,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_layout_changed(_screen: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Default host behavior until `FUN_081779c8` is ported.
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_SCREEN_LAYOUT_ASSIGN_OPS: ScreenLayoutAssignOps = ScreenLayoutAssignOps {
    layout_changed: missing_layout_changed,
};

/// Replaceable host boundary for the unported notification routine.
#[cfg(not(target_arch = "arm"))]
pub static mut SCREEN_LAYOUT_ASSIGN_OPS: ScreenLayoutAssignOps = DEFAULT_SCREEN_LAYOUT_ASSIGN_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn layout_changed(screen: *mut u8) -> *mut u8 {
    unsafe { core::ptr::read_volatile(addr_of!(SCREEN_LAYOUT_ASSIGN_OPS.layout_changed))(screen) }
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn layout_changed(screen: *mut u8) -> *mut u8 {
    let retail_notification: ScreenLayoutChanged = unsafe { core::mem::transmute(0x081779c8usize) };
    unsafe { retail_notification(screen) }
}

/// app_screen_set_layout — original: `FUN_0817434c` @ `0x0817434c`
/// (28 bytes; **25 direct `bl` call sites**, all unconditional — zero
/// predicated forms — binary-verified).
///
/// Copies `layout` into the screen's embedded `StringObject`, its seventh
/// 32-bit word (`+0x1c`), then runs the layout-change notification and returns
/// that notification's result. The source is not NULL-guarded: as in stock,
/// `string_object_assign` dereferences a distinct source object.
///
/// # Safety
///
/// `screen` must be writable through its target word index 7, where a valid
/// `StringObject` begins; `layout` must be a valid `StringObject` pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_screen_set_layout(
    screen: *mut u8,
    layout: *const StringObject,
) -> *mut u8 {
    let layout_slot = unsafe { screen.cast::<u32>().add(7).cast::<StringObject>() };
    unsafe { string_object_assign(layout_slot, layout) };
    unsafe { layout_changed(screen) }
}

/// app_screen_set_layout_from_resource — original: `FUN_08174300` @
/// `0x08174300` (76 bytes; **25 direct `bl` call sites**, all unconditional —
/// zero predicated forms and zero tail branches — binary-scanned by decoding
/// every B/BL word in osos.dec; no DATA word holds the address, so it is
/// never dispatched virtually).
///
/// ```text
/// 08174300  push {r2, r3, r4, r5, r6, lr}  @ r2/r3 = the stack StringObject
/// 08174304  mov  r6, r0                    @ screen
/// 08174308  mov  r0, r1                    @ provider class id
/// 0817430c  mov  r5, r2                    @ string id
/// 08174310  mov  r4, #5                    @ provider interface class id
/// 08174314  bl   registry_lookup_by_id     @ 0x081d2184
/// 08174318  mov  r1, r4
/// 0817431c  bl   object_cast_to_class      @ 0x08275b9c
/// 08174320  mov  r1, r5
/// 08174324  bl   resource_chain_find_string @ 0x0827239c
/// 08174328  mov  r1, r0
/// 0817432c  mov  r0, sp                    @ &temporary
/// 08174330  bl   string_owner_embedded_init @ 0x0827735c
/// 08174334  mov  r1, r0
/// 08174338  mov  r0, r6
/// 0817433c  bl   app_screen_set_layout     @ 0x0817434c
/// 08174340  mov  r0, sp
/// 08174344  bl   string_object_destroy     @ 0x08277484
/// 08174348  pop  {r2, r3, r4, r5, r6, pc}
/// ```
///
/// The resource front-end of [`app_screen_set_layout`]: resolves the resource
/// provider registered under `provider_class_id`, downcasts it to class id 5
/// ([`RESOURCE_PROVIDER_CLASS_ID`]), asks it for the `"Str "` resource
/// `string_id`, wraps the resulting C string in a temporary two-word
/// `StringObject` on the stack, assigns that as the screen's layout name, and
/// destroys the temporary. Callers pass the result of `app_screen_get` as
/// `screen` with class ids such as 0x80 (@ 0x082257ac) and 0x7e00
/// (@ 0x081e106c).
///
/// There is no NULL guard anywhere in the chain, and none is needed: a
/// missing registration makes [`registry_lookup_by_id`] return NULL,
/// [`object_cast_to_class`] passes NULL through, and
/// [`resource_chain_find_string`] on a NULL chain head returns NULL, so the
/// temporary — and hence the screen's layout — is cleared through the
/// StringObject NULL-payload path, exactly as in stock.
///
/// Deliberate deviation — the return word is dead in stock: the final `bl`
/// leaves r0 = `string_object_destroy`'s `this`, a pointer into the collapsed
/// stack frame, and both sampled callers overwrite r0 on the very next
/// instruction (`mov r0, #0` @ 0x081e1070, `ldrb r0, [r4, #0xb0]` @
/// 0x082257b0). The port declares `void` and lets r0 fall out of the last
/// call identically.
///
/// # Safety
///
/// `screen` must be a valid app screen object as for
/// [`app_screen_set_layout`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_screen_set_layout_from_resource(
    screen: *mut u8,
    provider_class_id: u32,
    string_id: u32,
) {
    let instance = unsafe { registry_lookup_by_id(provider_class_id) }.cast::<FrameworkObject>();
    let provider = unsafe { object_cast_to_class(instance, RESOURCE_PROVIDER_CLASS_ID) }
        .cast::<ResourceProvider>();
    let payload = unsafe { resource_chain_find_string(provider, string_id) };
    let mut scratch = core::mem::MaybeUninit::<StringObject>::uninit();
    let layout = unsafe { string_owner_embedded_init(scratch.as_mut_ptr(), payload) };
    unsafe { app_screen_set_layout(screen, layout) };
    unsafe { string_object_destroy(layout) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;
    use crate::testing::SCREEN_LAYOUT_ASSIGN_TEST_LOCK;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALLBACK_SCREEN: AtomicUsize = AtomicUsize::new(0);
    const CALLBACK_RESULT: usize = 0xdecafbad;

    unsafe extern "C" fn recording_layout_changed(screen: *mut u8) -> *mut u8 {
        CALLBACK_SCREEN.store(screen as usize, Ordering::SeqCst);
        CALLBACK_RESULT as *mut u8
    }

    struct OpsRestore(ScreenLayoutAssignOps);

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(SCREEN_LAYOUT_ASSIGN_OPS).write_volatile(self.0);
            }
        }
    }

    #[repr(align(8))]
    struct ScreenBacking([u8; 64]);

    #[test]
    fn assigns_the_embedded_layout_before_notifying() {
        let _guard = SCREEN_LAYOUT_ASSIGN_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        CALLBACK_SCREEN.store(0, Ordering::SeqCst);

        let old_ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCREEN_LAYOUT_ASSIGN_OPS)) };
        unsafe {
            core::ptr::addr_of_mut!(SCREEN_LAYOUT_ASSIGN_OPS).write_volatile(ScreenLayoutAssignOps {
                layout_changed: recording_layout_changed,
            });
        }
        let _restore = OpsRestore(old_ops);

        let mut backing = ScreenBacking([0; 64]);
        // A 32-bit-target screen pointer may be only 4-byte aligned. Starting
        // it at +4 keeps its +0x1c StringObject naturally aligned on this host.
        let screen = unsafe { backing.0.as_mut_ptr().add(4) };
        let embedded = unsafe { screen.add(0x1c).cast::<StringObject>() };
        assert_eq!((embedded as usize) % core::mem::align_of::<StringObject>(), 0);
        unsafe {
            embedded.write(StringObject {
                vtable: &STRING_OBJECT_VTABLE,
                payload: 0x55usize as *mut u8,
            });
        }

        let result = unsafe { app_screen_set_layout(screen, embedded) };

        assert_eq!(result as usize, CALLBACK_RESULT);
        assert_eq!(CALLBACK_SCREEN.load(Ordering::SeqCst), screen as usize);
        // Passing the exact embedded object is self-assignment, so stock's
        // address guard leaves its payload untouched while still notifying.
        assert_eq!(unsafe { (*embedded).payload as usize }, 0x55);
    }

    // ---- app_screen_set_layout_from_resource ----

    use crate::app::registry::{
        FrameworkObject, Registry, RegistryEntry, RegistryVtable, CLASS_REGISTRY,
    };
    use crate::app::resource_chain::{
        ResourceFindFn, ResourceKind, ResourceProvider, ResourceReadFn, ResourceWriteFn,
    };
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS,
        STRING_OBJECT_ASSIGN_CSTR_OPS,
    };
    use crate::heap::veneers::tests::mock_heap;
    use crate::testing::{CLASS_REGISTRY_TEST_LOCK, STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK};
    use core::ptr::{null, null_mut};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// What the registry mock was asked for, in order.
    static mut REGISTRY_KEYS: Vec<u32> = Vec::new();
    /// What the provider's cast slot saw: `(object, class_id)`.
    static mut CAST_CALLS: Vec<(usize, u32)> = Vec::new();
    /// What the provider's find slot saw: `(kind, id)`.
    static mut FIND_CALLS: Vec<(u32, u32)> = Vec::new();
    /// What the modeled slot +0xc cleared, in order.
    static mut CLEAR_CALLS: Vec<usize> = Vec::new();

    static mut FIXTURE_CLASS_ID: u32 = 0;
    static mut FIXTURE_INSTANCE: *mut u8 = null_mut();
    static mut CAST_ACCEPTS: bool = false;
    static mut FIND_PAYLOAD: *const u8 = null();

    unsafe extern "C" fn fixture_index_of(_this: *mut Registry, key: *const u32) -> i32 {
        let key = unsafe { key.read() };
        unsafe { (*core::ptr::addr_of_mut!(REGISTRY_KEYS)).push(key) };
        if key == unsafe { core::ptr::read_volatile(core::ptr::addr_of!(FIXTURE_CLASS_ID)) } {
            0
        } else {
            -1
        }
    }

    unsafe extern "C" fn fixture_entry_at(
        _this: *mut Registry,
        _index: i32,
        out: *mut RegistryEntry,
    ) -> *mut RegistryEntry {
        unsafe {
            out.write(RegistryEntry {
                class_id: core::ptr::read_volatile(core::ptr::addr_of!(FIXTURE_CLASS_ID)),
                instance: core::ptr::read_volatile(core::ptr::addr_of!(FIXTURE_INSTANCE)),
            });
        }
        out
    }

    unsafe extern "C" fn unexpected_insert(_this: *mut Registry, _entry: *const RegistryEntry) -> usize {
        usize::MAX
    }

    unsafe extern "C" fn unexpected_assign_at(
        _this: *mut Registry,
        _index: i32,
        _entry: *const RegistryEntry,
    ) -> usize {
        usize::MAX
    }

    unsafe extern "C" fn unexpected_observable(_this: *mut Registry) -> *mut u8 {
        null_mut()
    }

    static FIXTURE_REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: unexpected_insert,
        unresolved_20: 0,
        assign_at: unexpected_assign_at,
        unresolved_28: [0; 5],
        entry_at: fixture_entry_at,
        unresolved_40: [0; 3],
        index_of: fixture_index_of,
        unresolved_50: [0; 4],
        has_pending_changes: unexpected_observable,
        notify_deferred: unexpected_observable,
        notify_changed: unexpected_observable,
    };

    /// One vtable serving both views of the fixture provider: slot +0x14 for
    /// `object_cast_to_class` and slots +0x58/+0x64/+0x68 for the resource
    /// chain, at the same word indices the two ported models expect.
    #[repr(C)]
    struct ProviderVtable {
        unresolved_00: [usize; 5],
        cast_to_class: unsafe extern "C" fn(this: *mut FrameworkObject, class_id: u32) -> *mut u8,
        unresolved_18: [usize; 16],
        read: ResourceReadFn,
        unresolved_5c: [usize; 2],
        find: ResourceFindFn,
        write: ResourceWriteFn,
    }

    #[repr(C)]
    struct FixtureProvider {
        vtable: *const ProviderVtable,
        state_below_next: [usize; 4],
        next: *mut ResourceProvider,
    }

    unsafe extern "C" fn fixture_cast_to_class(
        this: *mut FrameworkObject,
        class_id: u32,
    ) -> *mut u8 {
        unsafe { (*core::ptr::addr_of_mut!(CAST_CALLS)).push((this as usize, class_id)) };
        if class_id == RESOURCE_PROVIDER_CLASS_ID
            && unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CAST_ACCEPTS)) }
        {
            this.cast::<u8>()
        } else {
            null_mut()
        }
    }

    unsafe extern "C" fn fixture_find(
        _provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
        found: *mut *mut u8,
    ) -> u32 {
        unsafe { (*core::ptr::addr_of_mut!(FIND_CALLS)).push((kind.0, id)) };
        let payload = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(FIND_PAYLOAD)) };
        if payload.is_null() {
            return 0;
        }
        unsafe { found.write(payload as *mut u8) };
        1
    }

    unsafe extern "C" fn fixture_read(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn fixture_write(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
        _value: u32,
        _flags: u32,
    ) -> u32 {
        0
    }

    static PROVIDER_VTABLE: ProviderVtable = ProviderVtable {
        unresolved_00: [0; 5],
        cast_to_class: fixture_cast_to_class,
        unresolved_18: [0; 16],
        read: fixture_read,
        unresolved_5c: [0; 2],
        find: fixture_find,
        write: fixture_write,
    };

    /// Per-allocation backing storage for the modeled slot +0x8. Static
    /// buffers keep the test off the ported default heap (its region table
    /// truncates 64-bit host addresses to u32 — `heap/veneers.rs` mocks it
    /// out for the same reason).
    static mut PAYLOAD_BUFS: [[u8; 64]; 2] = [[0; 64]; 2];
    static mut PAYLOAD_BUF_NEXT: usize = 0;

    /// The modeled slot +0x8: static storage for the replacement payload.
    /// As in stock, the slot owns publishing the new storage into
    /// `this.payload` (`string_object_assign_payload` only copies into the
    /// returned buffer, it never writes the payload word itself).
    unsafe extern "C" fn heap_allocate_payload(
        this: *mut StringObject,
        requested_size: usize,
        _flags: u32,
    ) -> *mut u8 {
        assert!(requested_size <= 64);
        let index = unsafe { core::ptr::addr_of_mut!(PAYLOAD_BUF_NEXT).read() } % 2;
        unsafe { core::ptr::addr_of_mut!(PAYLOAD_BUF_NEXT).write(index + 1) };
        let storage = unsafe { (*core::ptr::addr_of_mut!(PAYLOAD_BUFS))[index].as_mut_ptr() };
        unsafe { core::ptr::addr_of_mut!((*this).payload).write(storage) };
        storage
    }

    /// The modeled slot +0xc: release the current payload and NULL the word.
    /// The payloads it ever sees here are static buffers, so there is nothing
    /// to free.
    unsafe extern "C" fn heap_clear_payload(this: *mut StringObject) {
        unsafe { (*core::ptr::addr_of_mut!(CLEAR_CALLS)).push(this as usize) };
        unsafe { core::ptr::addr_of_mut!((*this).payload).write(null_mut()) };
    }

    /// Holds the seam locks, installs every fixture, and restores
    /// defaults on drop (the guard fields drop after `Drop::drop` runs).
    /// The heap mock keeps the ported `string_object_destroy`'s
    /// `free_wrapper` off the real default heap.
    struct ResourceFixture {
        old_layout_ops: ScreenLayoutAssignOps,
        old_registry_vtable: *const RegistryVtable,
        _registry_lock: MutexGuard<'static, ()>,
        _layout_lock: MutexGuard<'static, ()>,
        _cstr_lock: MutexGuard<'static, ()>,
        _heap_lock: MutexGuard<'static, ()>,
    }

    impl ResourceFixture {
        fn install(class_id: u32, provider: *mut u8, payload: *const u8, cast_accepts: bool) -> Self {
            let registry_lock = CLASS_REGISTRY_TEST_LOCK
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let layout_lock = SCREEN_LAYOUT_ASSIGN_TEST_LOCK
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let cstr_lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let heap_lock = mock_heap();
            CALLBACK_SCREEN.store(0, Ordering::SeqCst);
            let old_layout_ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCREEN_LAYOUT_ASSIGN_OPS)) };
            let old_registry_vtable = unsafe { CLASS_REGISTRY.vtable };
            unsafe {
                (*core::ptr::addr_of_mut!(REGISTRY_KEYS)).clear();
                (*core::ptr::addr_of_mut!(CAST_CALLS)).clear();
                (*core::ptr::addr_of_mut!(FIND_CALLS)).clear();
                (*core::ptr::addr_of_mut!(CLEAR_CALLS)).clear();
                core::ptr::addr_of_mut!(FIXTURE_CLASS_ID).write_volatile(class_id);
                core::ptr::addr_of_mut!(FIXTURE_INSTANCE).write_volatile(provider);
                core::ptr::addr_of_mut!(FIND_PAYLOAD).write_volatile(payload);
                core::ptr::addr_of_mut!(CAST_ACCEPTS).write_volatile(cast_accepts);
                core::ptr::addr_of_mut!(PAYLOAD_BUF_NEXT).write_volatile(0);
                CLASS_REGISTRY.vtable = &FIXTURE_REGISTRY_VTABLE;
                core::ptr::addr_of_mut!(SCREEN_LAYOUT_ASSIGN_OPS).write_volatile(
                    ScreenLayoutAssignOps { layout_changed: recording_layout_changed },
                );
                core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(
                    StringObjectAssignCstrOps {
                        allocate_payload: heap_allocate_payload,
                        clear_payload: heap_clear_payload,
                    },
                );
            }
            ResourceFixture {
                old_layout_ops,
                old_registry_vtable,
                _registry_lock: registry_lock,
                _layout_lock: layout_lock,
                _cstr_lock: cstr_lock,
                _heap_lock: heap_lock,
            }
        }
    }

    impl Drop for ResourceFixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(SCREEN_LAYOUT_ASSIGN_OPS).write_volatile(self.old_layout_ops);
                core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS)
                    .write_volatile(DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS);
                CLASS_REGISTRY.vtable = self.old_registry_vtable;
                core::ptr::addr_of_mut!(FIND_PAYLOAD).write_volatile(null());
            }
        }
    }

    /// Initializes `backing`'s embedded layout StringObject at +0x1c with
    /// `payload` (ownership stays with the caller) and returns the screen
    /// pointer. Borrows rather than returns the backing so the screen pointer
    /// cannot dangle off a moved value.
    unsafe fn fixture_screen(backing: &mut ScreenBacking, payload: *mut u8) -> *mut u8 {
        let screen = unsafe { backing.0.as_mut_ptr().add(4) };
        let embedded = unsafe { screen.add(0x1c).cast::<StringObject>() };
        assert_eq!((embedded as usize) % core::mem::align_of::<StringObject>(), 0);
        unsafe {
            embedded.write(StringObject { vtable: &STRING_OBJECT_VTABLE, payload });
        }
        screen
    }

    #[test]
    fn resolves_the_resource_string_and_sets_it_as_the_layout() {
        let mut provider = FixtureProvider {
            vtable: &PROVIDER_VTABLE,
            state_below_next: [0; 4],
            next: null_mut(),
        };
        let provider_ptr = unsafe { core::ptr::addr_of_mut!(provider) }.cast::<u8>();
        let _fixture = ResourceFixture::install(0x80, provider_ptr, b"Genius\0".as_ptr(), true);
        let mut backing = ScreenBacking([0; 64]);
        let screen = unsafe { fixture_screen(&mut backing, null_mut()) };

        unsafe { app_screen_set_layout_from_resource(screen, 0x80, 0x1234) };

        assert_eq!(unsafe { (*core::ptr::addr_of!(REGISTRY_KEYS)).clone() }, std::vec![0x80]);
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(CAST_CALLS)).clone() },
            std::vec![(provider_ptr as usize, RESOURCE_PROVIDER_CLASS_ID)]
        );
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(FIND_CALLS)).clone() },
            std::vec![(ResourceKind::STRING.0, 0x1234)]
        );
        let embedded = unsafe { screen.add(0x1c).cast::<StringObject>() };
        let payload = unsafe { (*embedded).payload };
        assert!(!payload.is_null(), "the layout string was assigned, not cleared");
        assert_eq!(unsafe { core::ffi::CStr::from_ptr(payload.cast()) }.to_bytes(), b"Genius");
        assert_eq!(CALLBACK_SCREEN.load(Ordering::SeqCst), screen as usize);
    }

    #[test]
    fn missing_registration_clears_the_layout_and_still_notifies() {
        static mut OLD_LAYOUT: [u8; 10] = *b"OldLayout\0";
        let _fixture = ResourceFixture::install(0x80, null_mut(), null(), false);
        let old = unsafe { (*core::ptr::addr_of_mut!(OLD_LAYOUT)).as_mut_ptr() };
        let mut backing = ScreenBacking([0; 64]);
        let screen = unsafe { fixture_screen(&mut backing, old) };

        // 0x7e00 is not in the fixture registry, so the lookup fails.
        unsafe { app_screen_set_layout_from_resource(screen, 0x7e00, 0x1234) };

        assert_eq!(unsafe { (*core::ptr::addr_of!(REGISTRY_KEYS)).clone() }, std::vec![0x7e00]);
        assert!(unsafe { (*core::ptr::addr_of!(CAST_CALLS)).is_empty() }, "NULL instance short-circuits the cast");
        assert!(unsafe { (*core::ptr::addr_of!(FIND_CALLS)).is_empty() }, "NULL chain head never dispatches find");
        let embedded = unsafe { screen.add(0x1c).cast::<StringObject>() };
        assert!(
            unsafe { (*embedded).payload.is_null() },
            "the NULL lookup propagated to a layout clear"
        );
        // Slot +0xc fired for the temporary and again for the embedded object.
        assert_eq!(unsafe { (*core::ptr::addr_of!(CLEAR_CALLS)).len() }, 2);
        assert_eq!(CALLBACK_SCREEN.load(Ordering::SeqCst), screen as usize);
    }

    #[test]
    fn a_refused_downcast_clears_the_layout_without_asking_the_provider() {
        let mut provider = FixtureProvider {
            vtable: &PROVIDER_VTABLE,
            state_below_next: [0; 4],
            next: null_mut(),
        };
        let provider_ptr = unsafe { core::ptr::addr_of_mut!(provider) }.cast::<u8>();
        // Registered, but the cast to class id 5 refuses.
        let _fixture = ResourceFixture::install(0x80, provider_ptr, b"Genius\0".as_ptr(), false);
        let mut backing = ScreenBacking([0; 64]);
        let screen = unsafe { fixture_screen(&mut backing, null_mut()) };

        unsafe { app_screen_set_layout_from_resource(screen, 0x80, 0x1234) };

        assert_eq!(
            unsafe { (*core::ptr::addr_of!(CAST_CALLS)).clone() },
            std::vec![(provider_ptr as usize, RESOURCE_PROVIDER_CLASS_ID)]
        );
        assert!(unsafe { (*core::ptr::addr_of!(FIND_CALLS)).is_empty() });
        assert_eq!(CALLBACK_SCREEN.load(Ordering::SeqCst), screen as usize);
    }
}
