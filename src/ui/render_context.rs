//! Resolving the render context associated with a UI element.
//!
//! - `ui_element_resolve_render_context` — original: `FUN_082a2670` @
//!   0x082a2670 (56 bytes; 76 direct `bl` call sites).
//!
//! Call-site evidence identifies the returned object as a rendering context:
//! callers pass it to the coordinate-origin helpers at 0x0828cb64/0x0828d9b4,
//! inspect its drawing-enabled flag at +0xf0, and use its bitmap surface at
//! +0x5c (for example 0x0816d3f0). The UI element owns a direct context at
//! +0x3c, with its parent link at +0x34. If none of the elements in the chain
//! owns one, the root's virtual method at +0x5c supplies an owner object whose
//! +0x104 field is the render context.

/// Byte offset of a UI element's parent link (`ldr r0,[r2,#0x34]`).
const PARENT_OFFSET: usize = 0x34;
/// Byte offset of a UI element's directly assigned render context
/// (`ldr r0,[r0,#0x3c]`).
const RENDER_CONTEXT_OFFSET: usize = 0x3c;
/// Byte offset of the root element's fallback virtual method
/// (`ldr r1,[vtable,#0x5c]`).
const ROOT_RENDER_OWNER_METHOD_OFFSET: usize = 0x5c;
/// Byte offset of the render context inside the fallback owner object's
/// result (`ldr r0,[r0,#0x104]`).
const RENDER_CONTEXT_IN_OWNER_OFFSET: usize = 0x104;

/// Root virtual method called when no element has a direct render context.
type RootRenderOwnerMethod = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// ui_element_resolve_render_context — original: `FUN_082a2670` @
/// 0x082a2670 (56 bytes).
///
/// Walk `element` and then each `parent` link at +0x34, returning the first
/// non-NULL direct render context at +0x3c. When no element in the chain has
/// one, call the root's vtable method at +0x5c with the root as `this`, then
/// return the render context at +0x104 of its result. The original makes no
/// NULL check on either the initial element, vtable, fallback result, or that
/// final context field.
///
/// The byte-offset accesses intentionally use unaligned reads: offsets are
/// four-byte aligned in the 32-bit retailOS layout but need not be pointer-size
/// aligned in the 64-bit host fixtures.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_resolve_render_context(element: *mut u8) -> *mut u8 {
    let mut current = element;
    loop {
        let render_context = current.add(RENDER_CONTEXT_OFFSET).cast::<u32>().read();
        if render_context != 0 {
            return render_context as usize as *mut u8;
        }

        let parent = current.add(PARENT_OFFSET).cast::<u32>().read();
        if parent != 0 {
            current = parent as usize as *mut u8;
            continue;
        }

        let vtable = current.cast::<u32>().read();
        let root_render_owner: RootRenderOwnerMethod =
            core::mem::transmute((vtable as *const u8).add(ROOT_RENDER_OWNER_METHOD_OFFSET).cast::<u32>().read());
        let owner = root_render_owner(current);
        return owner
            .add(RENDER_CONTEXT_IN_OWNER_OFFSET)
            .cast::<u32>()
            .read() as usize as *mut u8;
    }
}

/// Host form of [`ui_element_resolve_render_context`]. The device has
/// 32-bit pointers and can directly load each aligned word; host fixtures use
/// native-width pointers in those same byte offsets, requiring unaligned
/// pointer-sized loads.
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn ui_element_resolve_render_context(element: *mut u8) -> *mut u8 {
    let mut current = element;
    loop {
        let render_context = current.add(RENDER_CONTEXT_OFFSET).cast::<*mut u8>().read_unaligned();
        if !render_context.is_null() {
            return render_context;
        }

        let parent = current.add(PARENT_OFFSET).cast::<*mut u8>().read_unaligned();
        if !parent.is_null() {
            current = parent;
            continue;
        }

        let vtable = current.cast::<*const u8>().read_unaligned();
        let root_render_owner = vtable
            .add(ROOT_RENDER_OWNER_METHOD_OFFSET)
            .cast::<RootRenderOwnerMethod>()
            .read_unaligned();
        let owner = root_render_owner(current);
        return owner
            .add(RENDER_CONTEXT_IN_OWNER_OFFSET)
            .cast::<*mut u8>()
            .read_unaligned();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    const NODE_BYTES: usize = RENDER_CONTEXT_OFFSET + core::mem::size_of::<*mut u8>();
    const OWNER_BYTES: usize = RENDER_CONTEXT_IN_OWNER_OFFSET + core::mem::size_of::<*mut u8>();
    const VTABLE_BYTES: usize = ROOT_RENDER_OWNER_METHOD_OFFSET + core::mem::size_of::<RootRenderOwnerMethod>();

    /// Vtable fallback state is global only so an `extern "C"` test method can
    /// observe it. Serializing tests ensures independent fixtures never race.
    static FALLBACK_LOCK: Mutex<()> = Mutex::new(());
    static mut FALLBACK_OWNER: *mut u8 = ptr::null_mut();
    static mut FALLBACK_THIS: *mut u8 = ptr::null_mut();
    static mut FALLBACK_CALLS: u32 = 0;

    unsafe extern "C" fn root_render_owner(this: *mut u8) -> *mut u8 {
        FALLBACK_THIS = this;
        FALLBACK_CALLS += 1;
        FALLBACK_OWNER
    }

    struct Node {
        bytes: [u8; NODE_BYTES],
    }

    impl Node {
        fn new() -> Self {
            Self { bytes: [0; NODE_BYTES] }
        }

        fn ptr(&mut self) -> *mut u8 {
            self.bytes.as_mut_ptr()
        }

        unsafe fn set_parent(&mut self, parent: *mut u8) {
            self.ptr().add(PARENT_OFFSET).cast::<*mut u8>().write_unaligned(parent);
        }

        unsafe fn set_render_context(&mut self, render_context: *mut u8) {
            self.ptr()
                .add(RENDER_CONTEXT_OFFSET)
                .cast::<*mut u8>()
                .write_unaligned(render_context);
        }

        unsafe fn set_vtable(&mut self, vtable: *const u8) {
            self.ptr().cast::<*const u8>().write_unaligned(vtable);
        }
    }

    struct Owner {
        bytes: [u8; OWNER_BYTES],
    }

    impl Owner {
        fn new(render_context: *mut u8) -> Self {
            let mut owner = Self { bytes: [0; OWNER_BYTES] };
            unsafe {
                owner
                    .bytes
                    .as_mut_ptr()
                    .add(RENDER_CONTEXT_IN_OWNER_OFFSET)
                    .cast::<*mut u8>()
                    .write_unaligned(render_context);
            }
            owner
        }

        fn ptr(&mut self) -> *mut u8 {
            self.bytes.as_mut_ptr()
        }
    }

    struct Vtable {
        bytes: [u8; VTABLE_BYTES],
    }

    impl Vtable {
        fn root_fallback() -> Self {
            let mut vtable = Self { bytes: [0; VTABLE_BYTES] };
            unsafe {
                vtable
                    .bytes
                    .as_mut_ptr()
                    .add(ROOT_RENDER_OWNER_METHOD_OFFSET)
                    .cast::<RootRenderOwnerMethod>()
                    .write_unaligned(root_render_owner);
            }
            vtable
        }

        fn ptr(&self) -> *const u8 {
            self.bytes.as_ptr()
        }
    }

    fn prepare_fallback(owner: *mut u8) {
        unsafe {
            FALLBACK_OWNER = owner;
            FALLBACK_THIS = ptr::null_mut();
            FALLBACK_CALLS = 0;
        }
    }

    #[test]
    fn direct_context_on_the_first_node_returns_without_walking_or_falling_back() {
        let _lock = FALLBACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut first = Node::new();
        let mut parent = Node::new();
        let mut direct_context = [0u8; 1];
        let mut parent_context = [0u8; 1];
        let mut owner = Owner::new(ptr::null_mut());
        prepare_fallback(owner.ptr());

        unsafe {
            first.set_parent(parent.ptr());
            first.set_render_context(direct_context.as_mut_ptr());
            parent.set_render_context(parent_context.as_mut_ptr());
            assert_eq!(
                ui_element_resolve_render_context(first.ptr()),
                direct_context.as_mut_ptr()
            );
            assert_eq!(FALLBACK_CALLS, 0);
        }
    }

    #[test]
    fn walks_to_the_first_ancestor_with_a_direct_context() {
        let _lock = FALLBACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut first = Node::new();
        let mut middle = Node::new();
        let mut root = Node::new();
        let mut ancestor_context = [0u8; 1];
        let mut owner = Owner::new(ptr::null_mut());
        prepare_fallback(owner.ptr());

        unsafe {
            first.set_parent(middle.ptr());
            middle.set_parent(root.ptr());
            root.set_render_context(ancestor_context.as_mut_ptr());
            assert_eq!(
                ui_element_resolve_render_context(first.ptr()),
                ancestor_context.as_mut_ptr()
            );
            assert_eq!(FALLBACK_CALLS, 0);
        }
    }

    #[test]
    fn null_direct_contexts_use_the_root_vtable_fallback() {
        let _lock = FALLBACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut first = Node::new();
        let mut root = Node::new();
        let vtable = Vtable::root_fallback();
        let mut fallback_context = [0u8; 1];
        let mut owner = Owner::new(fallback_context.as_mut_ptr());
        prepare_fallback(owner.ptr());

        unsafe {
            first.set_parent(root.ptr());
            root.set_vtable(vtable.ptr());
            assert_eq!(
                ui_element_resolve_render_context(first.ptr()),
                fallback_context.as_mut_ptr()
            );
            assert_eq!(FALLBACK_CALLS, 1);
            assert_eq!(FALLBACK_THIS, root.ptr());
        }
    }

    #[test]
    fn a_single_node_chain_uses_that_node_as_the_fallback_root() {
        let _lock = FALLBACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut only = Node::new();
        let vtable = Vtable::root_fallback();
        let mut fallback_context = [0u8; 1];
        let mut owner = Owner::new(fallback_context.as_mut_ptr());
        prepare_fallback(owner.ptr());

        unsafe {
            only.set_vtable(vtable.ptr());
            assert_eq!(
                ui_element_resolve_render_context(only.ptr()),
                fallback_context.as_mut_ptr()
            );
            assert_eq!(FALLBACK_CALLS, 1);
            assert_eq!(FALLBACK_THIS, only.ptr());
        }
    }
}
