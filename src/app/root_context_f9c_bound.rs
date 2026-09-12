//! Shared-interface tree/mutex and root-context `+0xf9c` construction.
//!
//! Port: [`shared_interface_tree_mutex_construct`] — original:
//! `FUN_0813e9ec` @ `0x0813e9ec`. Raw ARM establishes 172 bytes of code
//! followed by three literal-pool words, for a true 184-byte extent
//! `0x0813e9ec..0x0813eaa4`; the separately linked next function begins
//! with `cmp r0, #0` at `0x0813eaa4`. Decoding every ARM B/BL immediate in
//! `osos.dec` found exactly ten inbound direct `bl` sites
//! (`0x080fe348`, `0x0811ee1c`, `0x081436f8`, `0x0814a938`, `0x08168a9c`,
//! `0x081aa35c`, `0x081b7610`, `0x081cc7d4`, `0x0829df40`, and
//! `0x082c86e8`), all unconditional; there are no predicated calls or
//! plain-`b` tail calls. No aligned image word equals its entry address, so
//! it is not data-dispatched.
//!
//! The base constructor installs the shared interface-base vtable, zeroes the
//! embedded word-key tree, allocates and self-links its sentinel, constructs
//! the mutex at `+0x20`, sets its byte at `+0x3c` to two, then installs the
//! final tree/mutex vtable, conditionally snapshots one of two root-context
//! resource words at `+0x40`, and writes the supplied mode byte at `+0x44`.
//! Neither vtable gives a recoverable class identity; the name states the
//! verified object shape rather than inventing one.
//!
//! Its two direct callees are the ported
//! [`word_key_set_allocate_node`](crate::cxx::word_key_set::word_key_set_allocate_node)
//! @ `0x083c00dc` and
//! [`cxx_mutex_construct`](crate::cxx::mutex::cxx_mutex_construct) @
//! `0x08261e28`.
//!
//! Deliberate deviations: the host representation widens pointer-bearing
//! tree fields to keep them disjoint; target layout assertions retain the
//! original offsets. The ARM call leaves the mutex constructor's otherwise
//! unused argument registers as ABI scratch after node allocation; the port
//! supplies zeroes for those scope seeds, whose attr initializer overwrites
//! them before use.

use crate::app::context_scope::app_root_object;
use crate::cxx::mutex::cxx_mutex_construct;
use crate::cxx::word_key_set::{
    word_key_set_allocate_node, WordKeySet, WordKeySetNodePool,
};

/// Initial interface vtable loaded from the pool word at `0x0813ea98`.
pub const SHARED_INTERFACE_BASE_VTABLE: u32 = 0x089a_75c8;

/// Final tree/mutex vtable loaded from the pool word at `0x0813ea9c`.
pub const SHARED_INTERFACE_TREE_MUTEX_VTABLE: u32 = 0x0898_50c4;

/// Literal vtable value loaded from the pool word at `0x08168ac4`.
pub const ROOT_CONTEXT_F9C_BOUND_VTABLE: u32 = 0x0898_80f0;

const ROOT_CONTEXT_WORD_INDEX: usize = 0x30 / core::mem::size_of::<u32>();
const ROOT_CONTEXT_F9C_WORD_INDEX: usize = 0xf9c / core::mem::size_of::<u32>();
const ROOT_CONTEXT_RESOURCE_WORD_INDEX: usize = 0xf7c / core::mem::size_of::<u32>();
const MUTEX_STATUS_OFFSET: usize = 0x1c;

/// The 0x48-byte base object the constructor establishes.
///
/// On the 32-bit target, the tree at `+0x04` occupies 0x1c bytes and the
/// opaque mutex wrapper at `+0x20` occupies 0x20 bytes. On a 64-bit host,
/// [`WordKeySet`] naturally expands around its pointer fields; named fields
/// preserve the relationships without overlapping them.
#[repr(C)]
pub struct SharedInterfaceTreeMutex {
    /// +0x00: shared interface vtable.
    pub vtable: u32,
    /// +0x04: word-keyed tree and its node-pool state.
    pub tree: WordKeySet,
    /// +0x20: C++ mutex wrapper on target.
    pub mutex: [u8; 0x20],
    /// +0x40: root-context resource selected by `kind` when it is 0 or 1.
    pub kind_resource: u32,
    /// +0x44: mode byte.
    pub mode: u8,
    /// +0x45..+0x47: untouched trailing bytes.
    pub trailing: [u8; 3],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x48] = [0; core::mem::size_of::<SharedInterfaceTreeMutex>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(SharedInterfaceTreeMutex, tree)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::offset_of!(SharedInterfaceTreeMutex, mutex)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x40] = [0; core::mem::offset_of!(SharedInterfaceTreeMutex, kind_resource)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x44] = [0; core::mem::offset_of!(SharedInterfaceTreeMutex, mode)];

/// The root-context binding reuses the complete shared-interface base object.
pub type RootContextF9cBound = SharedInterfaceTreeMutex;

/// shared_interface_tree_mutex_construct — original: `FUN_0813e9ec` @
/// `0x0813e9ec` (184 bytes including its three literal-pool words; ten
/// verified direct `bl` callers, all unconditional).
///
/// Installs the interface-base then tree/mutex vtable; makes an empty word-key
/// tree with a self-linked sentinel; constructs the mutex; marks its `+0x1c`
/// byte as two; stores resource `kind` 0 or 1 from the app root; writes
/// `mode`; and returns `this`. Neither `this` nor the root-context pointers
/// are NULL-checked, exactly as the ARM stores and loads require.
///
/// # Safety
///
/// `this` must name writable storage for a [`SharedInterfaceTreeMutex`]. If
/// `kind < 2`, the runtime app root, its `+0x30` pointer, and the selected
/// `+0xf7c`/`+0xf80` word must be aligned and readable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn shared_interface_tree_mutex_construct(
    this: *mut SharedInterfaceTreeMutex,
    mode: u8,
    kind: u32,
) -> *mut SharedInterfaceTreeMutex {
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*this).vtable),
        SHARED_INTERFACE_BASE_VTABLE,
    );

    let tree = core::ptr::addr_of_mut!((*this).tree);
    let pool = tree.cast::<WordKeySetNodePool>();
    (*pool).chunk_head = core::ptr::null_mut();
    (*pool).free_list = core::ptr::null_mut();
    (*pool).bump = core::ptr::null_mut();
    (*pool).bump_end = core::ptr::null_mut();
    (*tree).header = core::ptr::null_mut();
    (*tree).node_count = 0;
    (*tree).multi_insert = 0;
    (*tree).comparator = 0;

    let header = word_key_set_allocate_node(tree);
    (*tree).header = header;
    (*header).parent = core::ptr::null_mut();
    (*header).left = header;
    (*header).right = header;

    let mutex = core::ptr::addr_of_mut!((*this).mutex).cast::<u8>();
    cxx_mutex_construct(mutex, SHARED_INTERFACE_BASE_VTABLE as usize, 0, 0);
    mutex.add(MUTEX_STATUS_OFFSET).write(2);
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*this).vtable),
        SHARED_INTERFACE_TREE_MUTEX_VTABLE,
    );

    if kind < 2 {
        let root_context = (app_root_object() as *const u32)
            .add(ROOT_CONTEXT_WORD_INDEX)
            .read() as usize as *const u32;
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*this).kind_resource),
            root_context
                .add(ROOT_CONTEXT_RESOURCE_WORD_INDEX + kind as usize)
                .read(),
        );
    }
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).mode), mode);
    this
}

/// root_context_f9c_bound_construct — original: `FUN_08168a8c` @
/// `0x08168a8c` (56 bytes).
///
/// Calls the shared-interface base constructor with zero mode and kind,
/// replaces its vtable, snapshots the root context's `+0xf9c` word, and
/// writes `mode` at `+0x44`. Neither the base result nor either root-context
/// pointer is NULL-checked, matching the ARM loads and stores.
///
/// # Safety
///
/// `this` must meet the 0x48-byte base-object requirements and name writable
/// [`RootContextF9cBound`] storage. The runtime app root, its `+0x30` u32
/// pointer, and that object's `+0xf9c` word must be aligned and readable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn root_context_f9c_bound_construct(
    this: *mut RootContextF9cBound,
    mode: u8,
) -> *mut RootContextF9cBound {
    let bound = shared_interface_tree_mutex_construct(this, 0, 0);
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*bound).vtable),
        ROOT_CONTEXT_F9C_BOUND_VTABLE,
    );

    let root_context = (app_root_object() as *const u32)
        .add(ROOT_CONTEXT_WORD_INDEX)
        .read() as usize as *const u32;
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*bound).kind_resource),
        root_context.add(ROOT_CONTEXT_F9C_WORD_INDEX).read(),
    );
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*bound).mode), mode);
    bound
}

/// Literal-pool base at `0x08139de8`; the instance cache is its `+0x08`
/// word (`0x089cca28`).
pub static mut ROOT_CONTEXT_F9C_BOUND_INSTANCE: *mut RootContextF9cBound =
    core::ptr::null_mut();

/// RetailOS helper entered by the sole `bl` in
/// [`root_context_f9c_bound_instance`]. It allocates 0x48 bytes through
/// `operator_new`, then tail-branches to [`root_context_f9c_bound_construct`]
/// with mode zero.
pub const ROOT_CONTEXT_F9C_BOUND_INSTANCE_CONSTRUCT_TARGET_ADDRESS: usize = 0x0825_a010;

/// ABI of the unported allocation-and-construction helper at
/// [`ROOT_CONTEXT_F9C_BOUND_INSTANCE_CONSTRUCT_TARGET_ADDRESS`].
pub type RootContextF9cBoundInstanceConstruct =
    unsafe extern "C" fn() -> *mut RootContextF9cBound;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_root_context_f9c_bound_instance_construct(
) -> *mut RootContextF9cBound {
    let construct: RootContextF9cBoundInstanceConstruct =
        core::mem::transmute(ROOT_CONTEXT_F9C_BOUND_INSTANCE_CONSTRUCT_TARGET_ADDRESS);
    construct()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_root_context_f9c_bound_instance_construct(
) -> *mut RootContextF9cBound {
    panic!("root_context_f9c_bound_instance_construct requires helper 0x0825a010")
}

/// Active boundary for the unported allocation-and-construction helper.
#[cfg(target_os = "none")]
pub static mut ROOT_CONTEXT_F9C_BOUND_INSTANCE_CONSTRUCT: RootContextF9cBoundInstanceConstruct =
    retail_root_context_f9c_bound_instance_construct;

/// Active host boundary for the unported allocation-and-construction helper.
#[cfg(not(target_os = "none"))]
pub static mut ROOT_CONTEXT_F9C_BOUND_INSTANCE_CONSTRUCT: RootContextF9cBoundInstanceConstruct =
    missing_root_context_f9c_bound_instance_construct;

#[inline(always)]
unsafe fn root_context_f9c_bound_instance_construct_target() -> RootContextF9cBoundInstanceConstruct {
    core::ptr::read_volatile(core::ptr::addr_of!(ROOT_CONTEXT_F9C_BOUND_INSTANCE_CONSTRUCT))
}

/// root_context_f9c_bound_instance — original: `FUN_08139dbc` @
/// `0x08139dbc` (**44 bytes**: 40 bytes of code plus the `0x089cca20`
/// literal-pool word at `0x08139de8`; next independent function begins at
/// `0x08139dec`).
///
/// Returns the lazily allocated root-context `+0xf9c` binding cached at
/// `0x089cca28`. The cache is reloaded on every path. On a NULL cache it calls
/// the 24-byte helper at `0x0825a010`, stores its returned pointer before
/// checking it, then terminates through `heap_panic` if construction failed.
///
/// A full-image ARM B/BL decode found exactly **eight** inbound direct calls,
/// all unconditional `bl` (0x08139384, 0x081393b8, 0x081393d4, 0x0813962c,
/// 0x081399a8, 0x08139cd8, 0x08139d08, and 0x08139d34): zero predicated
/// forms and zero plain-`b` tails. No aligned image word equals the entry
/// address, so it is never data-dispatched.
///
/// # Deliberate deviation
///
/// `FUN_0825a010` is unported. Device builds call its verified fixed address
/// through a volatile seam; host tests install a recorder. Its raw body is
/// fully understood (allocate 0x48 bytes then tail-call the ported
/// [`root_context_f9c_bound_construct`] with zero mode), but retaining the
/// helper boundary preserves this function's one call dependency.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.root_context_f9c_bound_instance"
)]
pub unsafe extern "C" fn root_context_f9c_bound_instance() -> *mut RootContextF9cBound {
    let cache = core::ptr::addr_of_mut!(ROOT_CONTEXT_F9C_BOUND_INSTANCE);
    if cache.read_volatile().is_null() {
        let instance = root_context_f9c_bound_instance_construct_target()();
        cache.write_volatile(instance);
        if instance.is_null() {
            crate::heap::veneers::heap_panic();
        }
    }
    cache.read_volatile()
}

/// RetailOS entry address of the unported destructor body reached by the
/// two stock tail veneers.
pub const ROOT_CONTEXT_F9C_BOUND_DESTRUCT_TARGET_ADDRESS: usize = 0x0825_a028;

/// ABI of the unported destructor body at
/// [`ROOT_CONTEXT_F9C_BOUND_DESTRUCT_TARGET_ADDRESS`].
pub type RootContextF9cBoundDestruct =
    unsafe extern "C" fn(*mut RootContextF9cBound) -> *mut RootContextF9cBound;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_root_context_f9c_bound_destruct(
    this: *mut RootContextF9cBound,
) -> *mut RootContextF9cBound {
    let destruct: RootContextF9cBoundDestruct =
        core::mem::transmute(ROOT_CONTEXT_F9C_BOUND_DESTRUCT_TARGET_ADDRESS);
    destruct(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_root_context_f9c_bound_destruct(
    _this: *mut RootContextF9cBound,
) -> *mut RootContextF9cBound {
    panic!("root_context_f9c_bound_destruct requires destructor body 0x0825a028")
}

/// Active boundary for the unported destructor body.
#[cfg(target_os = "none")]
pub static mut ROOT_CONTEXT_F9C_BOUND_DESTRUCT: RootContextF9cBoundDestruct =
    retail_root_context_f9c_bound_destruct;

/// Active host boundary for the unported destructor body.
#[cfg(not(target_os = "none"))]
pub static mut ROOT_CONTEXT_F9C_BOUND_DESTRUCT: RootContextF9cBoundDestruct =
    missing_root_context_f9c_bound_destruct;

#[inline(always)]
unsafe fn root_context_f9c_bound_destruct_target() -> RootContextF9cBoundDestruct {
    core::ptr::read_volatile(core::ptr::addr_of!(ROOT_CONTEXT_F9C_BOUND_DESTRUCT))
}

/// root_context_f9c_bound_destruct — original: `thunk_FUN_0825a028` @
/// `0x08168ae4` (4 bytes; **12** verified direct `bl` callers).
///
/// Raw ARM is exactly `b 0x0813eabc`; that first tail veneer is exactly
/// `b 0x0825a028`, the unported destructor body. The separately linked next
/// function starts at `0x08168ae8`, proving that the extent is the one branch
/// word Ghidra reports. The preceding `0x08168acc` deleting destructor
/// NULL-checks this same object, calls the first veneer, and branches to
/// `operator_delete`; this is its non-deleting counterpart.
///
/// The algorithm therefore forwards `this` and propagates the target's
/// return unchanged. A complete decode of every ARM B/BL immediate in
/// `osos.dec` finds 12 inbound calls, all unconditional `bl` (no predicated
/// forms): `0x0812fa24`, `0x081425f8`, `0x08142614`, `0x081b58b4`,
/// `0x081b5d8c`, `0x081f8aa0`, `0x081f8b78`, `0x081f8e90`, `0x081f8ed8`,
/// `0x081f8fe4`, `0x08210b4c`, and `0x08211870`. No aligned image data word
/// equals either veneer or body address, so this is not data-dispatched.
///
/// # Deliberate deviation
///
/// The two stock tail branches become a volatile injectable call boundary.
/// `FUN_0825a028` is unported: device builds call its fixed retailOS address,
/// while host tests install a recorder. The wrapper deliberately retains no
/// NULL guard; the target owns that behavior.
///
/// # Safety
///
/// `this` must satisfy the unported destructor body's requirements. It is
/// forwarded even when NULL, exactly as the ARM veneer does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.root_context_f9c_bound_destruct"
)]
pub unsafe extern "C" fn root_context_f9c_bound_destruct(
    this: *mut RootContextF9cBound,
) -> *mut RootContextF9cBound {
    root_context_f9c_bound_destruct_target()(this)
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::context_scope::APP_ROOT_OBJECT;
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, APP_ROOT_TEST_LOCK,
    };
    use core::ptr;
    use std::sync::Mutex;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;

    static DESTRUCT_LOCK: Mutex<()> = Mutex::new(());
    static mut DESTRUCT_CALLS: u32 = 0;
    static mut DESTRUCT_INPUTS: [*mut RootContextF9cBound; 2] = [ptr::null_mut(); 2];
    static mut DESTRUCT_RETURN: *mut RootContextF9cBound = ptr::null_mut();

    static INSTANCE_LOCK: Mutex<()> = Mutex::new(());
    static mut INSTANCE_CONSTRUCT_CALLS: u32 = 0;
    static mut INSTANCE_CONSTRUCT_RETURN: *mut RootContextF9cBound = ptr::null_mut();

    unsafe extern "C" fn recording_instance_construct() -> *mut RootContextF9cBound {
        INSTANCE_CONSTRUCT_CALLS += 1;
        INSTANCE_CONSTRUCT_RETURN
    }

    struct InstanceRestore {
        construct: RootContextF9cBoundInstanceConstruct,
        instance: *mut RootContextF9cBound,
    }

    impl Drop for InstanceRestore {
        fn drop(&mut self) {
            unsafe {
                ROOT_CONTEXT_F9C_BOUND_INSTANCE_CONSTRUCT = self.construct;
                ROOT_CONTEXT_F9C_BOUND_INSTANCE = self.instance;
                INSTANCE_CONSTRUCT_CALLS = 0;
                INSTANCE_CONSTRUCT_RETURN = ptr::null_mut();
            }
        }
    }

    unsafe extern "C" fn recording_destruct(
        this: *mut RootContextF9cBound,
    ) -> *mut RootContextF9cBound {
        let call = DESTRUCT_CALLS as usize;
        DESTRUCT_INPUTS[call] = this;
        DESTRUCT_CALLS += 1;
        DESTRUCT_RETURN
    }

    struct DestructRestore {
        destruct: RootContextF9cBoundDestruct,
    }

    impl Drop for DestructRestore {
        fn drop(&mut self) {
            unsafe {
                ROOT_CONTEXT_F9C_BOUND_DESTRUCT = self.destruct;
                DESTRUCT_CALLS = 0;
                DESTRUCT_INPUTS = [ptr::null_mut(); 2];
                DESTRUCT_RETURN = ptr::null_mut();
            }
        }
    }

    const TREE_ARENA_SIZE: usize = 0x2000;

    #[repr(C, align(8))]
    struct TreeArena([u8; TREE_ARENA_SIZE]);

    static mut TREE_ARENA: TreeArena = TreeArena([0; TREE_ARENA_SIZE]);
    static mut TREE_ARENA_USED: usize = 0;

    unsafe extern "C" fn tree_arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = TREE_ARENA_USED;
        let aligned = (size + 7) & !7;
        if used + aligned > TREE_ARENA_SIZE {
            return ptr::null_mut();
        }
        TREE_ARENA_USED = used + aligned;
        core::ptr::addr_of_mut!(TREE_ARENA.0).cast::<u8>().add(used)
    }

    unsafe extern "C" fn tree_arena_create(
        descriptor: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        descriptor.cast()
    }

    fn tree_heap() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            TREE_ARENA_USED = 0;
            (*core::ptr::addr_of_mut!(HEAP_OPS)).alloc = tree_arena_alloc;
            (*core::ptr::addr_of_mut!(HEAP_OPS)).create = tree_arena_create;
        }
        guard
    }

    struct Restore {
        root: *mut u8,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                APP_ROOT_OBJECT = self.root;
            }
        }
    }

    fn object(value: u32, mode: u8, trailing: [u8; 3]) -> RootContextF9cBound {
        let mut object = unsafe {
            core::mem::MaybeUninit::<RootContextF9cBound>::zeroed().assume_init()
        };
        object.kind_resource = value;
        object.mode = mode;
        object.trailing = trailing;
        object
    }

    #[test]
    fn constructs_tree_mutex_and_binds_root_context_for_edge_kinds() {
        let _guard = APP_ROOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap = tree_heap();
        let Some(slab) = try_map_u32_slab(hints::ROOT_CONTEXT_F9C_BOUND, 0x3000) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let root = slab;
        let context = unsafe { slab.add(0x1000) };
        let previous_root = unsafe { APP_ROOT_OBJECT };
        unsafe {
            root.cast::<u32>().add(ROOT_CONTEXT_WORD_INDEX).write(context as usize as u32);
        }
        let restore = unsafe {
            APP_ROOT_OBJECT = root;
            Restore { root: previous_root }
        };

        let mut unbound = object(0x5555_5555, 0x77, [0x88; 3]);
        unsafe {
            let result = shared_interface_tree_mutex_construct(
                ptr::addr_of_mut!(unbound),
                u8::MAX,
                2,
            );
            assert_eq!(result, ptr::addr_of_mut!(unbound));
            assert_eq!(unbound.vtable, SHARED_INTERFACE_TREE_MUTEX_VTABLE);
            assert_eq!(unbound.kind_resource, 0x5555_5555, "kind >= 2 preserves +0x40");
            assert_eq!(unbound.mode, u8::MAX);
            assert_eq!(unbound.trailing, [0x88; 3], "does not write past +0x44");
            assert!(!unbound.tree.header.is_null());
            assert!((*unbound.tree.header).parent.is_null());
            assert_eq!((*unbound.tree.header).left, unbound.tree.header);
            assert_eq!((*unbound.tree.header).right, unbound.tree.header);
            assert_eq!(unbound.mutex[MUTEX_STATUS_OFFSET], 2);

            context
                .cast::<u32>()
                .add(ROOT_CONTEXT_RESOURCE_WORD_INDEX + 1)
                .write(0x0123_4567);
            let mut kind_one = object(0x5555_5555, 0x77, [0x88; 3]);
            let result = shared_interface_tree_mutex_construct(
                ptr::addr_of_mut!(kind_one),
                0x11,
                1,
            );
            assert_eq!(result, ptr::addr_of_mut!(kind_one));
            assert_eq!(kind_one.kind_resource, 0x0123_4567);
            assert_eq!(kind_one.mode, 0x11);

            context
                .cast::<u32>()
                .add(ROOT_CONTEXT_RESOURCE_WORD_INDEX)
                .write(0x7654_3210);
            let mut kind_zero = object(0x5555_5555, 0x77, [0x88; 3]);
            let result = shared_interface_tree_mutex_construct(
                ptr::addr_of_mut!(kind_zero),
                0x22,
                0,
            );
            assert_eq!(result, ptr::addr_of_mut!(kind_zero));
            assert_eq!(kind_zero.kind_resource, 0x7654_3210);
            assert_eq!(kind_zero.mode, 0x22);


            context.cast::<u32>().add(ROOT_CONTEXT_F9C_WORD_INDEX).write(u32::MAX);
            let mut bound = object(0x2222_2222, 0x33, [0x44; 3]);
            let result = root_context_f9c_bound_construct(ptr::addr_of_mut!(bound), u8::MAX);
            assert_eq!(result, ptr::addr_of_mut!(bound));
            assert_eq!(bound.vtable, ROOT_CONTEXT_F9C_BOUND_VTABLE);
            assert_eq!(bound.kind_resource, u32::MAX);
            assert_eq!(bound.mode, u8::MAX);
            assert_eq!(bound.trailing, [0x44; 3], "the byte store preserves trailing padding");

            context.cast::<u32>().add(ROOT_CONTEXT_F9C_WORD_INDEX).write(0);
            let mut zero_bound = object(0x6666_6666, 0x77, [0x99; 3]);
            let result = root_context_f9c_bound_construct(ptr::addr_of_mut!(zero_bound), 0);
            assert_eq!(result, ptr::addr_of_mut!(zero_bound));
            assert_eq!(zero_bound.kind_resource, 0);
            assert_eq!(zero_bound.mode, 0);
            assert_eq!(zero_bound.trailing, [0x99; 3]);
        }

        drop(restore);
    }

    #[test]
    fn instance_caches_constructor_result_and_bypasses_constructor_when_live() {
        let _guard = INSTANCE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut expected = object(0x0123_4567, 0x89, [0xab, 0xcd, 0xef]);
        let restore = unsafe {
            let restore = InstanceRestore {
                construct: ROOT_CONTEXT_F9C_BOUND_INSTANCE_CONSTRUCT,
                instance: ROOT_CONTEXT_F9C_BOUND_INSTANCE,
            };
            ROOT_CONTEXT_F9C_BOUND_INSTANCE = ptr::null_mut();
            ROOT_CONTEXT_F9C_BOUND_INSTANCE_CONSTRUCT = recording_instance_construct;
            INSTANCE_CONSTRUCT_RETURN = ptr::addr_of_mut!(expected);
            restore
        };

        unsafe {
            assert_eq!(
                root_context_f9c_bound_instance(),
                ptr::addr_of_mut!(expected),
                "cold cache returns the helper's result"
            );
            assert_eq!(INSTANCE_CONSTRUCT_CALLS, 1, "cold cache enters the helper once");
            assert_eq!(
                ROOT_CONTEXT_F9C_BOUND_INSTANCE,
                ptr::addr_of_mut!(expected),
                "the helper result is stored before returning"
            );

            assert_eq!(
                root_context_f9c_bound_instance(),
                ptr::addr_of_mut!(expected),
                "live cache is reloaded and returned unchanged"
            );
            assert_eq!(
                INSTANCE_CONSTRUCT_CALLS,
                1,
                "live cache bypasses the allocation-and-construction helper"
            );
        }

        drop(restore);
    }

    #[test]
    fn destruct_forwards_null_and_non_null_without_rewriting_the_target_result() {
        let _guard = DESTRUCT_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut input = object(0x2222_2222, 0x33, [0x44; 3]);
        let mut returned = object(0x6666_6666, 0x77, [0x88; 3]);
        let restore = unsafe {
            let restore = DestructRestore {
                destruct: ROOT_CONTEXT_F9C_BOUND_DESTRUCT,
            };
            ROOT_CONTEXT_F9C_BOUND_DESTRUCT = recording_destruct;
            DESTRUCT_RETURN = ptr::addr_of_mut!(returned);
            restore
        };

        unsafe {
            assert_eq!(
                root_context_f9c_bound_destruct(ptr::null_mut()),
                ptr::addr_of_mut!(returned)
            );
            assert_eq!(DESTRUCT_CALLS, 1);
            assert!(DESTRUCT_INPUTS[0].is_null(), "the veneer has no NULL guard");

            assert_eq!(
                root_context_f9c_bound_destruct(ptr::addr_of_mut!(input)),
                ptr::addr_of_mut!(returned)
            );
            assert_eq!(DESTRUCT_CALLS, 2);
            assert_eq!(DESTRUCT_INPUTS[1], ptr::addr_of_mut!(input));
        }

        drop(restore);
    }
}
