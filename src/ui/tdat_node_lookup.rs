//! Resolve a 'tdat' node in an owner's lookup context.
//!
//! `ui_tdat_node_lookup` — original: `FUN_0805132c` @ `0x0805132c` (44
//! bytes, exact extent `0x0805132c..0x08051358`). Raw ARM decoding finds one
//! unconditional outbound `bl` (to `ui_tdat_find_node_by_id` @ `0x08050d10`),
//! no predicated `bl` forms, and three unconditional inbound `bl` callsites.
//!
//! Algorithm: return null when the owner has no lookup context at `+0xf9c`.
//! Otherwise find a 'tdat' node using the owner element at `+0xf60` and the
//! first two identifier words, then tail-call the stock context resolver at
//! `0x080506bc` with the context and found node.
//!
//! Deliberate deviation: the context resolver has no `ported` names.yaml
//! entry, so target builds call its verified raw address and host builds use
//! an explicit seam. Rust returns normally instead of preserving the retail
//! tail branch; arguments and return value are unchanged.

use core::ptr;

use crate::ui::tdat_node_find::ui_tdat_find_node_by_id;

const OWNER_TDAT_ELEMENT_OFFSET: usize = 0xf60;
const OWNER_LOOKUP_CONTEXT_OFFSET: usize = 0xf9c;
const CONTEXT_NODE_RESOLVER_ADDRESS: usize = 0x0805_06bc;

/// ABI of the still-unported context resolver at `0x080506bc`.
pub type TdatContextNodeResolver = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_context_node_resolver(context: *mut u8, node: u32) -> *mut u8 {
    unsafe {
        core::mem::transmute::<usize, TdatContextNodeResolver>(CONTEXT_NODE_RESOLVER_ADDRESS)(context, node)
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_context_node_resolver(_context: *mut u8, _node: u32) -> *mut u8 {
    ptr::null_mut()
}

/// Host-replaceable boundary for the stock context resolver.
pub static mut TDAT_CONTEXT_NODE_RESOLVER: TdatContextNodeResolver = {
    #[cfg(target_os = "none")]
    { retail_context_node_resolver }
    #[cfg(not(target_os = "none"))]
    { missing_context_node_resolver }
};

#[inline(always)]
fn context_node_resolver() -> TdatContextNodeResolver {
    unsafe { ptr::read_volatile(ptr::addr_of!(TDAT_CONTEXT_NODE_RESOLVER)) }
}

/// ui_tdat_node_lookup — original: `FUN_0805132c` @ `0x0805132c` (44 bytes).
///
/// # Safety
///
/// `owner` must be readable through `+0xf9f` when non-null. If its lookup
/// context is non-null, the element pointer at `+0xf60` and the structures
/// required by the node finder and context resolver must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_tdat_node_lookup")]
#[inline(never)]
pub unsafe extern "C" fn ui_tdat_node_lookup(
    owner: *const u8,
    node_id_low: u32,
    node_id_high: u32,
    _unused: u32,
) -> *mut u8 {
    let context = unsafe { (owner.add(OWNER_LOOKUP_CONTEXT_OFFSET) as *const *mut u8).read() };
    if context.is_null() {
        return ptr::null_mut();
    }

    let element = unsafe { (owner.add(OWNER_TDAT_ELEMENT_OFFSET) as *const *const u8).read() };
    let node = unsafe { ui_tdat_find_node_by_id(element, node_id_low, node_id_high) };
    unsafe { context_node_resolver()(context, node) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static RESOLVER_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: (*mut u8, u32) = (ptr::null_mut(), 0);
    static mut RESULT: *mut u8 = ptr::null_mut();

    struct ResolverReset(TdatContextNodeResolver);

    impl Drop for ResolverReset {
        fn drop(&mut self) {
            unsafe { TDAT_CONTEXT_NODE_RESOLVER = self.0; }
        }
    }

    unsafe extern "C" fn resolver(context: *mut u8, node: u32) -> *mut u8 {
        unsafe {
            CALL = (context, node);
            RESULT
        }
    }

    #[test]
    fn absent_context_returns_null_without_resolving() {
        let _lock = RESOLVER_LOCK.lock();
        let previous = unsafe { TDAT_CONTEXT_NODE_RESOLVER };
        let _reset = ResolverReset(previous);
        unsafe { TDAT_CONTEXT_NODE_RESOLVER = resolver; }
        let mut owner = [0u8; OWNER_LOOKUP_CONTEXT_OFFSET + 4];

        let result = unsafe { ui_tdat_node_lookup(owner.as_mut_ptr(), 1, 2, 3) };

        assert!(result.is_null());
    }

    #[test]
    fn present_context_forwards_found_node_to_context_resolver() {
        let _lock = RESOLVER_LOCK.lock();
        let previous = unsafe { TDAT_CONTEXT_NODE_RESOLVER };
        let _reset = ResolverReset(previous);
        let mut owner = [0u8; OWNER_LOOKUP_CONTEXT_OFFSET + 4];
        let mut context = [0u8; 1];
        let expected = 0x1234usize as *mut u8;
        unsafe {
            (owner.as_mut_ptr().add(OWNER_LOOKUP_CONTEXT_OFFSET) as *mut *mut u8).write(context.as_mut_ptr());
            TDAT_CONTEXT_NODE_RESOLVER = resolver;
            CALL = (ptr::null_mut(), 0);
            RESULT = expected;
        }

        let result = unsafe { ui_tdat_node_lookup(owner.as_mut_ptr(), 0x11, 0x22, 0x33) };

        assert_eq!(result, expected);
        assert_eq!(unsafe { CALL }, (context.as_mut_ptr(), 0));
    }
}
