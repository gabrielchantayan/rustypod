//! `tree_lookup_result_write_cc874` — original: `FUN_083dbfec` @ `0x083dbfec`
//! (40 bytes).
//!
//! Raw `osos.dec` establishes the exact ten-word extent from `push
//! {r1,r2,r3,r4,r5,lr}` through `pop {r1,r2,r3,r4,r5,pc}`; `0x083dc014`
//! begins the next real function. It makes one unconditional plain `bl`, to
//! the retail tree lookup at `0x083cc874`, and no predicated `bl` calls.
//! Whole-image A32 decoding finds two inbound unconditional plain `bl` sites
//! (0x0819ee2c and 0x0819eee4), with no predicated forms. The lookup writes a
//! target-width node pointer and one-byte match flag into a stack result; this
//! wrapper copies exactly those five bytes to `result`.
//!
//! Deliberate deviation: host builds use a callable lookup seam because the
//! retail callee remains at its firmware address. The target invokes that
//! address directly.

#[repr(C)]
pub struct TreeLookupResult {
    pub node: u32,
    pub matched: u8,
}

type RetailTreeLookup = unsafe extern "C" fn(*mut TreeLookupResult, *mut u8, *const u8);

#[cfg(target_os = "none")]
const RETAIL_TREE_LOOKUP_ADDRESS: usize = 0x083c_c874;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_tree_lookup(_: *mut TreeLookupResult, _: *mut u8, _: *const u8) {
    panic!("tree_lookup_result_write_cc874 requires a retail tree lookup fixture")
}

#[cfg(not(target_os = "none"))]
static mut RETAIL_TREE_LOOKUP: RetailTreeLookup = unavailable_tree_lookup;

/// Runs the retail tree lookup and copies its `{node, matched}` result.
///
/// # Safety
///
/// `result`, `tree`, and `key` must satisfy the retail lookup's object-layout
/// and lifetime requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tree_lookup_result_write_cc874(
    result: *mut TreeLookupResult,
    tree: *mut u8,
    key: *const u8,
) {
    #[cfg(target_os = "none")]
    let lookup: RetailTreeLookup = unsafe { core::mem::transmute(RETAIL_TREE_LOOKUP_ADDRESS) };
    #[cfg(not(target_os = "none"))]
    let lookup = unsafe { RETAIL_TREE_LOOKUP };

    let mut lookup_result = core::mem::MaybeUninit::<TreeLookupResult>::uninit();
    unsafe { lookup(lookup_result.as_mut_ptr(), tree, key) };
    let lookup_result = unsafe { lookup_result.assume_init() };
    unsafe {
        result.cast::<u32>().write_volatile(lookup_result.node);
        result.cast::<u8>().add(4).write_volatile(lookup_result.matched);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut LOOKUP_ARGUMENTS: (*mut u8, *const u8) = (core::ptr::null_mut(), core::ptr::null());

    unsafe extern "C" fn lookup_fixture(result: *mut TreeLookupResult, tree: *mut u8, key: *const u8) {
        unsafe {
            LOOKUP_ARGUMENTS = (tree, key);
            result.write(TreeLookupResult { node: 0x1234_5678, matched: 1 });
        }
    }

    #[test]
    fn copies_the_retail_lookup_result() {
        let tree = 0x1000usize as *mut u8;
        let key = 0x2000usize as *const u8;
        let mut result = TreeLookupResult { node: 0xffff_ffff, matched: 0xff };
        unsafe {
            let saved_lookup = RETAIL_TREE_LOOKUP;
            RETAIL_TREE_LOOKUP = lookup_fixture;
            tree_lookup_result_write_cc874(&mut result, tree, key);
            RETAIL_TREE_LOOKUP = saved_lookup;
        }
        assert_eq!(result.node, 0x1234_5678);
        assert_eq!(result.matched, 1);
        assert_eq!(unsafe { LOOKUP_ARGUMENTS }, (tree, key));
    }
}
