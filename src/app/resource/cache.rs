//! Resource callback dispatch and cache refresh helpers.
//!
//! [`resource_callback_dispatch`] is `FUN_0806b604` @ 0x0806b604 (136
//! bytes). It calls a callback for the root, then, only when that callback
//! succeeds and the root's `+0x1d` bit 0 is set, walks the root's `+0x20`
//! sibling chain. Marked children recurse; unmarked children are called
//! directly. The first nonzero callback status stops the depth-first walk.
//!
//! `resource_cache_refresh_get` is `FUN_08047020` @ 0x08047020 (60 bytes:
//! 56 bytes of code plus the callback literal at 0x0804705c). The object owns
//! a resource-callback root at `+0x40` and a three-field cache at `+0x618`: a
//! dirty byte, an auxiliary word, and the returned value. A nonzero dirty byte
//! or `force_refresh` clears all three fields, then dispatches
//! `0x080db63c` against the root. The callback repopulates the cache; its
//! status return is ignored.
//!
//! The callback literal enters an allocation-handler tail at 0x080db63c, not
//! a normal Rust-callable function. RetailOS enters it with the active node in
//! `r4` and the context in `r2`; the firmware-only indirect-call helper
//! preserves that recovered register contract.

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
/// Sibling link within a resource callback node.
const RESOURCE_CALLBACK_NEXT_OFFSET: usize = 0x08;
/// Flags byte within a resource callback node.
const RESOURCE_CALLBACK_FLAGS_OFFSET: usize = 0x1d;
/// First child in a resource callback node's child list.
const RESOURCE_CALLBACK_CHILD_OFFSET: usize = 0x20;
/// The flag that selects recursive child traversal.
const RESOURCE_CALLBACK_CHILDREN_FLAG: u8 = 1;
/// RetailOS status for a null root or callback.
const RESOURCE_CALLBACK_INVALID_ARGUMENT: i32 = -0x32;


/// Normal callback ABI used by [`resource_callback_dispatch`].
///
/// On firmware, `callback` is supplied as an entry address so the retail
/// allocation-handler tail can also rely on `r4 = node` and `r2 = context`.
/// Ordinary callbacks receive their documented `r0 = node`, `r1 = context`
/// arguments and return a status in `r0`.
pub type ResourceCallback = unsafe extern "C" fn(node: *mut u8, context: *mut u8) -> i32;

/// ABI exposed to the cache getter's replaceable dispatcher seam.
pub type ResourceCacheCallbackDispatch = unsafe extern "C" fn(
    resource_callback_root: *mut u8,
    callback: usize,
    context: *mut u8,
) -> i32;

/// Invokes a callback with the complete recovered ARM register contract.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn invoke_resource_callback(callback: usize, node: *mut u8, context: *mut u8) -> i32 {
    let status: i32;
    core::arch::asm!(
        "blx r5",
        inlateout("r0") node => status,
        in("r1") context,
        in("r2") context,
        in("r4") node,
        in("r5") callback,
        clobber_abi("C"),
    );
    status
}

/// Host implementation of the ordinary two-argument callback ABI.
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn invoke_resource_callback(callback: usize, node: *mut u8, context: *mut u8) -> i32 {
    let callback: ResourceCallback = core::mem::transmute(callback);
    callback(node, context)
}

/// resource_callback_dispatch — original: `FUN_0806b604` @ 0x0806b604
/// (136 bytes).
///
/// Calls `callback(root, context)` first. If it succeeds and root flag
/// `+0x1d & 1` is set, walks its `+0x20` child/sibling chain. A marked child
/// starts a recursive walk; an unmarked child is called directly. Every
/// nonzero callback result terminates immediately; null root or callback
/// returns `-0x32`.
///
/// # Safety
///
/// `resource_callback_root` and every reachable child must be valid,
/// writable-or-readable (as appropriate) resource nodes with fields at
/// `+0x08`, `+0x1d`, and `+0x20`. `callback` must be a valid code address
/// using the recovered ABI. As in retailOS, malformed links or callback
/// addresses are not guarded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_callback_dispatch(
    resource_callback_root: *mut u8,
    callback: usize,
    context: *mut u8,
) -> i32 {
    if resource_callback_root.is_null() || callback == 0 {
        return RESOURCE_CALLBACK_INVALID_ARGUMENT;
    }

    let status = invoke_resource_callback(callback, resource_callback_root, context);
    if status != 0 {
        return status;
    }
    if resource_callback_root
        .add(RESOURCE_CALLBACK_FLAGS_OFFSET)
        .read_volatile()
        & RESOURCE_CALLBACK_CHILDREN_FLAG
        == 0
    {
        return 0;
    }

    let mut node = resource_callback_root
        .add(RESOURCE_CALLBACK_CHILD_OFFSET)
        .cast::<*mut u8>()
        .read_volatile();
    while !node.is_null() {
        let status = if node.add(RESOURCE_CALLBACK_FLAGS_OFFSET).read_volatile()
            & RESOURCE_CALLBACK_CHILDREN_FLAG
            == 0
        {
            invoke_resource_callback(callback, node, context)
        } else {
            resource_callback_dispatch(node, callback, context)
        };
        if status != 0 {
            return status;
        }
        node = node
            .add(RESOURCE_CALLBACK_NEXT_OFFSET)
            .cast::<*mut u8>()
            .read_volatile();
    }
    0
}

/// Replaceable entry used by [`resource_cache_refresh_get`].
///
/// Firmware defaults to the recovered dispatcher. Host cache tests may
/// replace this slot to observe cache-side ordering without fabricating the
/// allocation-handler callback's behavior.
pub static mut RESOURCE_CACHE_CALLBACK_DISPATCH: ResourceCacheCallbackDispatch =
    resource_callback_dispatch;

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
    use std::vec::Vec;

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

    #[repr(align(8))]
    struct ResourceNode([u8; RESOURCE_CALLBACK_CHILD_OFFSET + core::mem::size_of::<*mut u8>()]);

    impl ResourceNode {
        fn new() -> Self {
            ResourceNode([0; RESOURCE_CALLBACK_CHILD_OFFSET + core::mem::size_of::<*mut u8>()])
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }

        unsafe fn set_flags(&mut self, flags: u8) {
            self.ptr()
                .add(RESOURCE_CALLBACK_FLAGS_OFFSET)
                .write_volatile(flags);
        }

        unsafe fn set_next(&mut self, next: *mut u8) {
            self.ptr()
                .add(RESOURCE_CALLBACK_NEXT_OFFSET)
                .cast::<*mut u8>()
                .write_volatile(next);
        }

        unsafe fn set_child(&mut self, child: *mut u8) {
            self.ptr()
                .add(RESOURCE_CALLBACK_CHILD_OFFSET)
                .cast::<*mut u8>()
                .write_volatile(child);
        }
    }

    static mut RESOURCE_CALLBACK_LOG: Vec<usize> = Vec::new();
    static mut RESOURCE_CALLBACK_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut RESOURCE_CALLBACK_STOP_NODE: *mut u8 = core::ptr::null_mut();
    static mut RESOURCE_CALLBACK_STOP_STATUS: i32 = 0;

    unsafe extern "C" fn record_resource_callback(node: *mut u8, context: *mut u8) -> i32 {
        (&mut *core::ptr::addr_of_mut!(RESOURCE_CALLBACK_LOG)).push(node as usize);
        RESOURCE_CALLBACK_CONTEXT = context;
        if node == RESOURCE_CALLBACK_STOP_NODE {
            RESOURCE_CALLBACK_STOP_STATUS
        } else {
            0
        }
    }

    fn begin_resource_callback_test() -> MutexGuard<'static, ()> {
        let guard = DISPATCH_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            (&mut *core::ptr::addr_of_mut!(RESOURCE_CALLBACK_LOG)).clear();
            RESOURCE_CALLBACK_CONTEXT = core::ptr::null_mut();
            RESOURCE_CALLBACK_STOP_NODE = core::ptr::null_mut();
            RESOURCE_CALLBACK_STOP_STATUS = 0;
        }
        guard
    }

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
                    .write_volatile(resource_callback_dispatch);
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
    fn resource_callback_dispatch_rejects_null_root_or_callback() {
        let _dispatch = begin_resource_callback_test();
        let mut node = ResourceNode::new();
        let mut context = 0u8;
        unsafe {
            assert_eq!(
                resource_callback_dispatch(
                    core::ptr::null_mut(),
                    record_resource_callback as usize,
                    core::ptr::addr_of_mut!(context),
                ),
                RESOURCE_CALLBACK_INVALID_ARGUMENT
            );
            assert_eq!(
                resource_callback_dispatch(node.ptr(), 0, core::ptr::addr_of_mut!(context)),
                RESOURCE_CALLBACK_INVALID_ARGUMENT
            );
            assert!(
                (&*core::ptr::addr_of!(RESOURCE_CALLBACK_LOG)).is_empty(),
                "invalid arguments do not call the callback"
            );
        }
    }

    #[test]
    fn resource_callback_dispatch_walks_marked_nodes_depth_first() {
        let _dispatch = begin_resource_callback_test();
        let mut root = ResourceNode::new();
        let mut first = ResourceNode::new();
        let mut branch = ResourceNode::new();
        let mut nested = ResourceNode::new();
        let mut after = ResourceNode::new();
        let mut context = 0u8;
        unsafe {
            root.set_flags(RESOURCE_CALLBACK_CHILDREN_FLAG);
            root.set_child(first.ptr());
            first.set_next(branch.ptr());
            branch.set_flags(RESOURCE_CALLBACK_CHILDREN_FLAG);
            branch.set_child(nested.ptr());
            branch.set_next(after.ptr());

            assert_eq!(
                resource_callback_dispatch(
                    root.ptr(),
                    record_resource_callback as usize,
                    core::ptr::addr_of_mut!(context),
                ),
                0
            );
            assert_eq!(
                (&*core::ptr::addr_of!(RESOURCE_CALLBACK_LOG)).as_slice(),
                &[
                    root.ptr() as usize,
                    first.ptr() as usize,
                    branch.ptr() as usize,
                    nested.ptr() as usize,
                    after.ptr() as usize,
                ],
                "marked siblings recurse before the parent chain advances"
            );
            assert_eq!(RESOURCE_CALLBACK_CONTEXT, core::ptr::addr_of_mut!(context));
        }
    }

    #[test]
    fn resource_callback_dispatch_returns_first_nonzero_status() {
        let _dispatch = begin_resource_callback_test();
        let mut root = ResourceNode::new();
        let mut child = ResourceNode::new();
        let mut context = 0u8;
        unsafe {
            root.set_flags(RESOURCE_CALLBACK_CHILDREN_FLAG);
            root.set_child(child.ptr());
            RESOURCE_CALLBACK_STOP_NODE = root.ptr();
            RESOURCE_CALLBACK_STOP_STATUS = -7;

            assert_eq!(
                resource_callback_dispatch(
                    root.ptr(),
                    record_resource_callback as usize,
                    core::ptr::addr_of_mut!(context),
                ),
                -7
            );
            assert_eq!(
                (&*core::ptr::addr_of!(RESOURCE_CALLBACK_LOG)).as_slice(),
                &[root.ptr() as usize],
                "a root callback failure prevents child traversal"
            );
        }
    }

    #[test]
    fn resource_callback_dispatch_stops_at_a_failing_direct_child() {
        let _dispatch = begin_resource_callback_test();
        let mut root = ResourceNode::new();
        let mut failing_child = ResourceNode::new();
        let mut skipped_sibling = ResourceNode::new();
        let mut context = 0u8;
        unsafe {
            root.set_flags(RESOURCE_CALLBACK_CHILDREN_FLAG);
            root.set_child(failing_child.ptr());
            failing_child.set_next(skipped_sibling.ptr());
            RESOURCE_CALLBACK_STOP_NODE = failing_child.ptr();
            RESOURCE_CALLBACK_STOP_STATUS = -9;

            assert_eq!(
                resource_callback_dispatch(
                    root.ptr(),
                    record_resource_callback as usize,
                    core::ptr::addr_of_mut!(context),
                ),
                -9
            );
            assert_eq!(
                (&*core::ptr::addr_of!(RESOURCE_CALLBACK_LOG)).as_slice(),
                &[root.ptr() as usize, failing_child.ptr() as usize],
                "a direct-child callback failure prevents later siblings"
            );
        }
    }

    #[test]
    fn resource_callback_dispatch_propagates_nested_failure_before_parent_siblings() {
        let _dispatch = begin_resource_callback_test();
        let mut root = ResourceNode::new();
        let mut branch = ResourceNode::new();
        let mut failing_grandchild = ResourceNode::new();
        let mut skipped_sibling = ResourceNode::new();
        let mut context = 0u8;
        unsafe {
            root.set_flags(RESOURCE_CALLBACK_CHILDREN_FLAG);
            root.set_child(branch.ptr());
            branch.set_flags(RESOURCE_CALLBACK_CHILDREN_FLAG);
            branch.set_child(failing_grandchild.ptr());
            branch.set_next(skipped_sibling.ptr());
            RESOURCE_CALLBACK_STOP_NODE = failing_grandchild.ptr();
            RESOURCE_CALLBACK_STOP_STATUS = -11;

            assert_eq!(
                resource_callback_dispatch(
                    root.ptr(),
                    record_resource_callback as usize,
                    core::ptr::addr_of_mut!(context),
                ),
                -11
            );
            assert_eq!(
                (&*core::ptr::addr_of!(RESOURCE_CALLBACK_LOG)).as_slice(),
                &[
                    root.ptr() as usize,
                    branch.ptr() as usize,
                    failing_grandchild.ptr() as usize,
                ],
                "a nested callback failure returns through recursion before parent siblings run"
            );
        }
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
