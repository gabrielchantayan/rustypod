//! Construction of a keyed event binding.
//!
//! `keyed_event_binding_construct` — original: `FUN_081de158` @
//! **0x081de158** (**76 bytes**, exactly `0x081de158..0x081de1a4`; the
//! following `push {r3, r4, r5, lr}` starts the sibling constructor at
//! 0x081de1a4). **12 unconditional `bl` call sites**, verified by decoding
//! every ARM `B`/`BL` word in `osos.dec`: 0x0817f094, 0x0817f180,
//! 0x08180b68, 0x08182074, 0x081821bc, 0x081833e4, 0x081835bc, 0x08183ab4,
//! 0x08183c10, 0x08183ebc, 0x0818422c, and 0x08184610. There are no
//! predicated or tail-branch call sites.
//!
//! # Algorithm
//!
//! The constructor records a 32-bit lookup key, the low byte of `kind`, and
//! a 32-bit context word; clears its state, embedded QuickDraw rectangle, and
//! trailing word; then obtains the ported 0x3c-byte element registry. It asks
//! the registry's unported ordered-map helper (`FUN_083db8f4`) for the value
//! slot belonging to a stack copy of `key` and stores `this` into that slot.
//! It returns `this`. Bytes +0x05..+0x07 are deliberately untouched, just as
//! the stock `strb` at +0x04 leaves them untouched.
//!
//! # Deliberate deviation
//!
//! `FUN_083db8f4` is not ported. On device this port calls that verified
//! function entry directly; the host-only function pointer below is an
//! injectable boundary for proving this constructor's writes and registration
//! arguments. The boundary is not an identity claim about that helper: only
//! its observed `(registry + 0x20, &key) -> writable value slot` ABI is used.

use crate::app::singletons::lazy_singleton_0x3c;
use crate::ui::rect::Rect;
#[cfg(target_os = "none")]
use crate::ui::rect::rect_clear;
#[cfg(not(target_os = "none"))]
use crate::ui::rect::rect_clear;

/// Target offset of the ordered-map object in the 0x3c-byte element registry.
const ELEMENT_REGISTRY_MAP_OFFSET: usize = 0x20;

// `rect_clear` must remain a call from this constructor. A volatile load
// prevents LLVM from replacing this direct firmware boundary with four stores.
#[cfg(target_os = "none")]
static RECT_CLEAR: unsafe extern "C" fn(*mut Rect) = rect_clear;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_binding_bounds(bounds: *mut Rect) {
    let clear = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RECT_CLEAR)) };
    unsafe { clear(bounds) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn clear_binding_bounds(bounds: *mut Rect) {
    unsafe { rect_clear(bounds) }
}

/// The 0x24-byte record initialized by `keyed_event_binding_construct`.
///
/// `context` remains a raw 32-bit word even when it represents a pointer at a
/// call site: the target ABI stores exactly one word, while a host pointer is
/// wider. The three bytes after `kind` intentionally model the padding the
/// original does not write.
#[repr(C)]
pub struct KeyedEventBinding {
    /// +0x00 — key used to locate this binding in the element registry.
    pub key: u32,
    /// +0x04 — event kind, narrowed by the original `strb`.
    pub kind: u8,
    /// +0x05..+0x07 — not initialized by this constructor.
    pub untouched_05: [u8; 3],
    /// +0x08 — caller-supplied context word.
    pub context: u32,
    /// +0x0c — cleared state word.
    pub state: u32,
    /// +0x10..+0x1f — cleared rectangle.
    pub bounds: Rect,
    /// +0x20 — cleared trailing word.
    pub opaque_20: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(KeyedEventBinding, kind)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(KeyedEventBinding, context)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(KeyedEventBinding, state)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(KeyedEventBinding, bounds)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::offset_of!(KeyedEventBinding, opaque_20)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x24] = [0; core::mem::size_of::<KeyedEventBinding>()];

/// ABI of `FUN_083db8f4`: yields the mapped value word for `key` in the
/// element registry's ordered map.
type ElementRegistrySlotForKey =
    unsafe extern "C" fn(registry_map: *mut u8, key: *const u32) -> *mut *mut KeyedEventBinding;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn element_registry_slot_for_key(
    registry_map: *mut u8,
    key: *const u32,
) -> *mut *mut KeyedEventBinding {
    let lookup: ElementRegistrySlotForKey = unsafe { core::mem::transmute(0x083d_b8f4usize) };
    unsafe { lookup(registry_map, key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_element_registry_slot_for_key(
    _registry_map: *mut u8,
    _key: *const u32,
) -> *mut *mut KeyedEventBinding {
    panic!("keyed_event_binding_construct requires FUN_083db8f4")
}

/// Host replacement for the unported ordered-map helper. Tests replace this
/// pointer while exercising the retail constructor's data flow.
#[cfg(not(target_os = "none"))]
pub static mut ELEMENT_REGISTRY_SLOT_FOR_KEY: ElementRegistrySlotForKey =
    missing_element_registry_slot_for_key;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn element_registry_slot_for_key(
    registry_map: *mut u8,
    key: *const u32,
) -> *mut *mut KeyedEventBinding {
    let lookup = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(ELEMENT_REGISTRY_SLOT_FOR_KEY))
    };
    unsafe { lookup(registry_map, key) }
}

/// Performs the stock stores and registration against an already acquired
/// element registry. Kept separate so host tests do not mutate the global
/// singleton cache owned by `lazy_singleton_0x3c`.
#[inline(always)]
unsafe fn initialize_binding(
    this: *mut KeyedEventBinding,
    key: u32,
    context: u32,
    kind: u32,
) {
    unsafe {
        (*this).key = key;
        (*this).kind = kind as u8;
        (*this).context = context;
        (*this).state = 0;
        (*this).opaque_20 = 0;
        rect_clear(core::ptr::addr_of_mut!((*this).bounds));
    }
}

/// Performs the variant's stores in the order used by
/// `keyed_event_binding_construct_with_state`.
#[inline(always)]
unsafe fn initialize_binding_with_state(
    this: *mut KeyedEventBinding,
    key: u32,
    context: u32,
    state: u32,
    kind: u32,
) {
    unsafe {
        (*this).key = key;
        (*this).kind = kind as u8;
        (*this).opaque_20 = 0;
        (*this).context = context;
        (*this).state = state;
        clear_binding_bounds(core::ptr::addr_of_mut!((*this).bounds));
    }
}

#[inline(always)]
unsafe fn register_binding_in_element_registry(
    this: *mut KeyedEventBinding,
    key: u32,
    registry: *mut u8,
) {
    unsafe {
        // The original passes a stack copy, not the just-stored object field.
        let key_copy = key;
        let slot = element_registry_slot_for_key(
            registry.add(ELEMENT_REGISTRY_MAP_OFFSET),
            core::ptr::addr_of!(key_copy),
        );
        slot.write(this);
    }
}

/// Performs the stock stores and registration against an already acquired
/// element registry. Kept separate so host tests do not mutate the global
/// singleton cache owned by `lazy_singleton_0x3c`.
#[inline(always)]
unsafe fn construct_in_element_registry(
    this: *mut KeyedEventBinding,
    key: u32,
    context: u32,
    kind: u32,
    registry: *mut u8,
) -> *mut KeyedEventBinding {
    unsafe {
        initialize_binding(this, key, context, kind);
        register_binding_in_element_registry(this, key, registry);
    }
    this
}

/// Performs the stock stores and registration against an already acquired
/// element registry for the state-bearing constructor.
#[inline(always)]
unsafe fn construct_with_state_in_element_registry(
    this: *mut KeyedEventBinding,
    key: u32,
    context: u32,
    state: u32,
    kind: u32,
    registry: *mut u8,
) -> *mut KeyedEventBinding {
    unsafe {
        initialize_binding_with_state(this, key, context, state, kind);
        register_binding_in_element_registry(this, key, registry);
    }
    this
}

/// keyed_event_binding_construct — original: `FUN_081de158` @ 0x081de158
/// (76 bytes; 12 unconditional `bl` call sites, binary-verified above).
///
/// # Safety
///
/// `this` must designate a writable, 0x24-byte aligned binding object. The
/// lazy 0x3c-byte element registry and its map at +0x20 must be initialized;
/// as in retailOS, neither pointer is checked for NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.keyed_event_binding_construct")]
pub unsafe extern "C" fn keyed_event_binding_construct(
    this: *mut KeyedEventBinding,
    key: u32,
    context: u32,
    kind: u32,
) -> *mut KeyedEventBinding {
    unsafe { initialize_binding(this, key, context, kind) };
    let registry = unsafe { lazy_singleton_0x3c() };
    unsafe { register_binding_in_element_registry(this, key, registry) };
    this
}

/// Construction of a keyed event binding that retains caller-supplied state.
///
/// `keyed_event_binding_construct_with_state` — original: `FUN_081de1f4` @
/// **0x081de1f4** (**80 bytes**, exactly `0x081de1f4..0x081de244`; followed
/// by the standalone `bx lr` at 0x081de244). **8 unconditional `bl` call
/// sites**, verified by decoding every ARM `B`/`BL` word in `osos.dec`:
/// 0x08180c80, 0x08180e10, 0x08180f54, 0x08182e40, 0x08183068, 0x08183844,
/// 0x08183864, and 0x081838d8. There are no predicated or tail-branch call
/// sites.
///
/// # Algorithm
///
/// Stores `key`, the low byte of `kind`, `context`, and `state`; clears the
/// embedded QuickDraw rectangle and trailing word; then registers `this` in
/// the 0x3c element registry's map (+0x20) under a stack copy of `key`.
/// Bytes +0x05..+0x07 remain untouched.
///
/// # Deliberate deviation
///
/// As with `keyed_event_binding_construct`, the still-stock
/// `FUN_083db8f4` map helper is called directly on device and through the
/// host-only injectable ABI boundary in tests. Its identity is not inferred.
/// On device the already-ported `rect_clear` is loaded through a volatile
/// function pointer so LLVM preserves the stock call boundary rather than
/// inlining its four zero stores.
///
/// # Safety
///
/// `this` must designate a writable, 0x24-byte aligned binding object. The
/// lazy 0x3c-byte element registry and its map at +0x20 must be initialized;
/// as in retailOS, neither pointer is checked for NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.keyed_event_binding_construct_with_state")]
pub unsafe extern "C" fn keyed_event_binding_construct_with_state(
    this: *mut KeyedEventBinding,
    key: u32,
    context: u32,
    state: u32,
    kind: u32,
) -> *mut KeyedEventBinding {
    unsafe { initialize_binding_with_state(this, key, context, state, kind) };
    let registry = unsafe { lazy_singleton_0x3c() };
    unsafe { register_binding_in_element_registry(this, key, registry) };
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SLOT: *mut KeyedEventBinding = ptr::null_mut();
    static mut SEEN_MAP: *mut u8 = ptr::null_mut();
    static mut SEEN_KEY: u32 = 0;
    static mut SEEN_KEY_POINTER: *const u32 = ptr::null();


    unsafe extern "C" fn record_registry_slot(
        registry_map: *mut u8,
        key: *const u32,
    ) -> *mut *mut KeyedEventBinding {
        unsafe {
            SEEN_MAP = registry_map;
            SEEN_KEY = key.read();
            SEEN_KEY_POINTER = key;

            ptr::addr_of_mut!(SLOT)
        }
    }

    unsafe fn install_slot_recorder() -> (MutexGuard<'static, ()>, ElementRegistrySlotForKey) {
        let guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(ELEMENT_REGISTRY_SLOT_FOR_KEY))
        };
        unsafe {
            SLOT = ptr::null_mut();
            SEEN_MAP = ptr::null_mut();
            SEEN_KEY = 0;
            SEEN_KEY_POINTER = ptr::null();

            ELEMENT_REGISTRY_SLOT_FOR_KEY = record_registry_slot;
        }
        (guard, previous)
    }

    unsafe fn restore_slot_recorder(
        previous: ElementRegistrySlotForKey,
        _guard: MutexGuard<'static, ()>,
    ) {
        unsafe { ELEMENT_REGISTRY_SLOT_FOR_KEY = previous }
    }

    #[test]
    fn it_initializes_a_binding_and_registers_its_keyed_slot() {
        let (guard, previous) = unsafe { install_slot_recorder() };
        let mut registry = [0u8; 0x3c];
        let mut binding = KeyedEventBinding {
            key: 0,
            kind: 0,
            untouched_05: [0xa5; 3],
            context: 0,
            state: u32::MAX,
            bounds: Rect { top: 7, left: -8, bottom: 9, right: -10 },
            opaque_20: u32::MAX,
        };

        let result = unsafe {
            construct_in_element_registry(
                ptr::addr_of_mut!(binding),
                0xfeed_beef,
                0xdead_c0de,
                0x1ab,
                registry.as_mut_ptr(),
            )
        };

        assert_eq!(result, ptr::addr_of_mut!(binding));
        assert_eq!(binding.key, 0xfeed_beef);
        assert_eq!(binding.kind, 0xab, "the retail strb truncates kind");
        assert_eq!(binding.untouched_05, [0xa5; 3], "strb leaves padding alone");
        assert_eq!(binding.context, 0xdead_c0de);
        assert_eq!(binding.state, 0);
        assert_eq!(binding.bounds, Rect::default());
        assert_eq!(binding.opaque_20, 0);
        unsafe {
            assert_eq!(SEEN_MAP, registry.as_mut_ptr().add(ELEMENT_REGISTRY_MAP_OFFSET));
            assert_eq!(SEEN_KEY, 0xfeed_beef, "the registry receives the key copy");
            assert_ne!(
                SEEN_KEY_POINTER,
                ptr::addr_of!(binding.key),
                "the retail call receives a stack key copy, not this->key",
            );
            assert_eq!(SLOT, ptr::addr_of_mut!(binding), "the located value slot receives this");
            restore_slot_recorder(previous, guard);
        }
    }

    #[test]
    fn it_initializes_a_state_bearing_binding_and_registers_its_keyed_slot() {
        let (guard, previous) = unsafe { install_slot_recorder() };
        let mut registry = [0u8; 0x3c];
        let mut binding = KeyedEventBinding {
            key: 0,
            kind: 0,
            untouched_05: [0xa5; 3],
            context: 0,
            state: 0,
            bounds: Rect { top: 7, left: -8, bottom: 9, right: -10 },
            opaque_20: u32::MAX,
        };

        let result = unsafe {
            construct_with_state_in_element_registry(
                ptr::addr_of_mut!(binding),
                0xfeed_beef,
                0xdead_c0de,
                0x2468_ace0,
                0x1ab,
                registry.as_mut_ptr(),
            )
        };

        assert_eq!(result, ptr::addr_of_mut!(binding));
        assert_eq!(binding.key, 0xfeed_beef);
        assert_eq!(binding.kind, 0xab, "the retail strb truncates kind");
        assert_eq!(binding.untouched_05, [0xa5; 3], "strb leaves padding alone");
        assert_eq!(binding.context, 0xdead_c0de);
        assert_eq!(binding.state, 0x2468_ace0);
        assert_eq!(binding.bounds, Rect::default());
        assert_eq!(binding.opaque_20, 0);
        unsafe {
            assert_eq!(SEEN_MAP, registry.as_mut_ptr().add(ELEMENT_REGISTRY_MAP_OFFSET));
            assert_eq!(SEEN_KEY, 0xfeed_beef, "the registry receives the key copy");
            assert_ne!(
                SEEN_KEY_POINTER,
                ptr::addr_of!(binding.key),
                "the retail call receives a stack key copy, not this->key",
            );
            assert_eq!(SLOT, ptr::addr_of_mut!(binding), "the located value slot receives this");
            restore_slot_recorder(previous, guard);
        }
    }
}
