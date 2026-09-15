//! `cg_expression_dependency_mask` — original: `FUN_082cda48` @
//! `0x082cda48` (128 bytes, all code; 11 direct `bl` call sites).
//!
//! Raw `osos.dec` runs from the prologue at `0x082cda48` through `pop
//! {r4-r8,pc}` at `0x082cdac4`; the next separately linked function starts
//! at `0x082cdac8`. Decoding every ARM `B`/`BL` word finds eleven calls to
//! this entry, all unconditional `bl` (zero predicated forms): two recursive
//! calls in this body, eight uses in its 0x082ccf94..0x082cd9b4 sibling
//! walkers, and one H.264-side use at `0x08367324`.
//!
//! ## Algorithm
//!
//! Builds a 64-bit dependency mask for an opaque expression node. A NULL node
//! returns zero. Tag `0x95` is a leaf: its target-width word at `+0x24` is
//! resolved through [`cg_dependency_mask_lookup`]. Every other tag recursively
//! collects `+0x0c`, then `+0x08`, and ORs those masks with the two sibling
//! collection helpers over `+0x10` and `+0x38`, in that exact order.
//!
//! ## Deviations
//!
//! The `+0x10` collection helper is ported in this module; the `+0x38`
//! collection helper remains a retailOS entry on target builds and a host ops
//! seam. Node links are raw 32-bit target words, so accesses use word indices
//! rather than host-width pointer fields.

/// The unported `+0x38` collection call made by
/// [`cg_expression_dependency_mask`].
#[derive(Clone, Copy)]
pub struct CgExpressionDependencyMaskOps {
    /// `FUN_082cd9b4` @ `0x082cd9b4`, called with the target word at +0x38.
    pub collect_field_38: unsafe extern "C" fn(context: *const u32, node: *const u8) -> u64,
}




#[cfg(target_os = "none")]
unsafe extern "C" fn retail_collect_field_38(context: *const u32, node: *const u8) -> u64 {
    let collect: unsafe extern "C" fn(*const u32, *const u8) -> u64 =
        core::mem::transmute(0x082c_d9b4usize);
    collect(context, node)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_collect_field_38(_context: *const u32, _node: *const u8) -> u64 {
    panic!("cg_expression_dependency_mask requires FUN_082cd9b4")
}

/// Wired defaults for [`CG_EXPRESSION_DEPENDENCY_MASK_OPS`].
#[cfg(target_os = "none")]
pub const DEFAULT_CG_EXPRESSION_DEPENDENCY_MASK_OPS: CgExpressionDependencyMaskOps =
    CgExpressionDependencyMaskOps {
        collect_field_38: retail_collect_field_38,
    };

/// Wired defaults for [`CG_EXPRESSION_DEPENDENCY_MASK_OPS`].
#[cfg(not(target_os = "none"))]
pub const DEFAULT_CG_EXPRESSION_DEPENDENCY_MASK_OPS: CgExpressionDependencyMaskOps =
    CgExpressionDependencyMaskOps {
        collect_field_38: missing_collect_field_38,
    };

/// Active binding for the unported retailOS dependency.
pub static mut CG_EXPRESSION_DEPENDENCY_MASK_OPS: CgExpressionDependencyMaskOps =
    DEFAULT_CG_EXPRESSION_DEPENDENCY_MASK_OPS;

#[inline(always)]
unsafe fn dependency_mask_ops() -> CgExpressionDependencyMaskOps {
    core::ptr::read_volatile(core::ptr::addr_of!(CG_EXPRESSION_DEPENDENCY_MASK_OPS))
}

/// Reads one aligned target word from an opaque expression node.
#[inline(always)]
unsafe fn node_word(node: *const u8, word_index: usize) -> u32 {
    node.cast::<u32>().add(word_index).read()
}

/// `cg_expression_dependency_mask` — original: `FUN_082cda48` @ `0x082cda48`.
///
/// Returns the 64-bit dependency mask of `node`; node links are 32-bit words
/// in the dependency lookup table.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_expression_dependency_mask(
    context: *const u32,
    node: *const u8,
) -> u64 {
    if node.is_null() {
        return 0;
    }

    if node.read() == 0x95 {
        return super::dependency_mask_lookup::cg_dependency_mask_lookup(context, node_word(node, 9));
    }

    let mut mask = cg_expression_dependency_mask(context, node_word(node, 3) as usize as *const u8);
    mask |= cg_expression_dependency_mask(context, node_word(node, 2) as usize as *const u8);
    mask |= super::expression_collection_dependency_mask::cg_expression_collection_dependency_mask(
        context,
        node_word(node, 4) as usize as *const u8,
    );
    mask |= (dependency_mask_ops().collect_field_38)(
        context,
        node_word(node, 14) as usize as *const u8,
    );
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    extern crate std;
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CG_EXPRESSION_DEPENDENCY_MASK, SLAB_LEN).map(|p| p as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());

    #[derive(Debug, Eq, PartialEq)]
    enum Call {
        Collect38 { context: usize, node: usize },
    }

    unsafe extern "C" fn record_collect_38(context: *const u32, node: *const u8) -> u64 {
        CALLS.lock().unwrap_or_else(|e| e.into_inner()).push(Call::Collect38 {
            context: context as usize,
            node: node as usize,
        });
        0x0010_0000_0000_0000
    }

    const RECORDING_OPS: CgExpressionDependencyMaskOps = CgExpressionDependencyMaskOps {
        collect_field_38: record_collect_38,
    };

    fn setup() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ptr::addr_of_mut!(CG_EXPRESSION_DEPENDENCY_MASK_OPS).write(RECORDING_OPS);
        }
        CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        guard
    }

    fn teardown() {
        unsafe {
            ptr::addr_of_mut!(CG_EXPRESSION_DEPENDENCY_MASK_OPS)
                .write(DEFAULT_CG_EXPRESSION_DEPENDENCY_MASK_OPS);
        }
    }

    fn slab() -> Option<*mut u8> {
        (*SLAB).map(|base| base as *mut u8)
    }

    unsafe fn write_word(at: *mut u8, offset: usize, value: u32) {
        at.add(offset).cast::<u32>().write(value);
    }

    fn target_word(pointer: *const u8) -> u32 {
        u32::try_from(pointer as usize).expect("fixture must be target-addressable")
    }

    #[test]
    fn null_node_returns_zero_without_dispatch() {
        let _guard = setup();
        assert_eq!(unsafe { cg_expression_dependency_mask(ptr::null(), ptr::null()) }, 0);
        assert!(CALLS.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
        teardown();
    }

    #[test]
    fn leaf_uses_only_its_identifier_word() {
        let _guard = setup();
        let Some(base) = slab() else {
            note_missing_u32_fixture(module_path!());
            teardown();
            return;
        };
        unsafe {
            ptr::write_bytes(base, 0, SLAB_LEN);
            let leaf = base.add(0x100);
            leaf.write(0x95);
            write_word(leaf, 0x24, 0x3333_4444);
            write_word(leaf, 0x08, target_word(base.add(0x200)));
            write_word(leaf, 0x0c, target_word(base.add(0x300)));
            write_word(leaf, 0x10, target_word(base.add(0x400)));
            write_word(leaf, 0x38, target_word(base.add(0x500)));
            let context = base.add(0x700).cast::<u32>();
            context.write(2);
            context.add(1).write(0x1111_2222);
            context.add(2).write(0x3333_4444);

            assert_eq!(cg_expression_dependency_mask(context, leaf), 2);
            assert!(CALLS.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
        }
        teardown();
    }

    #[test]
    fn non_leaf_recurses_then_ors_sibling_masks_in_assembly_order() {
        let _guard = setup();
        let Some(base) = slab() else {
            note_missing_u32_fixture(module_path!());
            teardown();
            return;
        };
        unsafe {
            ptr::write_bytes(base, 0, SLAB_LEN);
            let root = base.add(0x100);
            let first = base.add(0x200); // root +0x0c: first recursive call
            let second = base.add(0x300); // root +0x08: second recursive call
            let field_10 = base.add(0x400);
            let field_38 = base.add(0x500);
            root.write(0x40);
            write_word(root, 0x0c, target_word(first));
            write_word(root, 0x08, target_word(second));
            write_word(root, 0x10, target_word(field_10));
            write_word(root, 0x38, target_word(field_38));
            first.write(0x95);
            write_word(first, 0x24, 0x1111_2222);
            second.write(0x95);
            write_word(second, 0x24, 0x3333_4444);

            let context = base.add(0x700).cast::<u32>();
            context.write(2);
            context.add(1).write(0x1111_2222);
            context.add(2).write(0x3333_4444);
            assert_eq!(
                cg_expression_dependency_mask(context, root),
                0x0010_0000_0000_0003
            );
            assert_eq!(
                *CALLS.lock().unwrap_or_else(|e| e.into_inner()),
                [Call::Collect38 {
                    context: context as usize,
                    node: field_38 as usize,
                }]
            );
        }
        teardown();
    }
}
