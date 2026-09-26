use core::ptr;

/// RetailOS `FUN_083db32c` @ load address `0x083db32c`.
///
/// True extent: 160 bytes, from the prologue at `0x083db32c` through the
/// literal word at `0x083db3cc`; the next separately linked function starts
/// at `0x083db3d0`. Whole-image ARM decoding finds two inbound plain `bl`
/// calls (`0x080e40f0`, `0x082aaf8c`) and no predicated forms. The body makes
/// nine plain `bl` calls and no predicated calls. It builds an empty
/// string-vector key from `source`, performs the tree lookup-or-insert, then
/// destroys every temporary and returns the mapped value at result-node + 20.
///
/// Deliberate deviations: the three unported composite helpers remain opaque
/// operation slots; their ABIs and call ordering are preserved without naming
/// an unsupported container type.
pub type VectorInitialize = unsafe extern "C" fn(*mut u8);
pub type KeyConstruct = unsafe extern "C" fn(*mut u8, *const u8, *const u8, *mut u8, u32);
pub type QueryConstruct = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;
pub type TreeLookupOrInsert = unsafe extern "C" fn(*mut u32, *mut u8, *const u8);
pub type QueryDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;
pub type StringRelease = unsafe extern "C" fn(*mut u8);
pub type KeyDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;
pub type VectorDestroy = unsafe extern "C" fn(*mut u8);

#[derive(Clone, Copy)]
pub struct StringVectorMapLookupOrInsertOps {
    pub vector_initialize: VectorInitialize,
    pub key_construct: KeyConstruct,
    pub query_construct: QueryConstruct,
    pub tree_lookup_or_insert: TreeLookupOrInsert,
    pub query_destroy: QueryDestroy,
    pub string_release: StringRelease,
    pub key_destroy: KeyDestroy,
    pub vector_destroy: VectorDestroy,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vector_initialize(destination: *mut u8) {
    unsafe { core::mem::transmute::<usize, VectorInitialize>(0x083e_5aec)(destination) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_key_construct(destination: *mut u8, a: *const u8, b: *const u8, vector: *mut u8, flag: u32) {
    unsafe { core::mem::transmute::<usize, KeyConstruct>(0x0819_7ab8)(destination, a, b, vector, flag) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_query_construct(destination: *mut u8, key: *const u8) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, QueryConstruct>(0x0819_7b90)(destination, key) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tree_lookup_or_insert(result: *mut u32, tree: *mut u8, key: *const u8) {
    unsafe { core::mem::transmute::<usize, TreeLookupOrInsert>(0x083c_1d1c)(result, tree, key) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_query_destroy(query: *mut u8) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, QueryDestroy>(0x0819_7c28)(query) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_string_release(string: *mut u8) { unsafe { crate::cxx::string::cxx_string_release(string.cast()) } }
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_key_destroy(key: *mut u8) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, KeyDestroy>(0x0819_7c28)(key) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vector_destroy(vector: *mut u8) { unsafe { core::mem::transmute::<usize, VectorDestroy>(0x083e_5b88)(vector) } }

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_void(_: *mut u8) { panic!("install string-vector map lookup fixture") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_key(_: *mut u8, _: *const u8, _: *const u8, _: *mut u8, _: u32) { panic!("install string-vector map lookup fixture") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_query(_: *mut u8, _: *const u8) -> *mut u8 { panic!("install string-vector map lookup fixture") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_lookup(_: *mut u32, _: *mut u8, _: *const u8) { panic!("install string-vector map lookup fixture") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_destroy(_: *mut u8) -> *mut u8 { panic!("install string-vector map lookup fixture") }

#[cfg(target_os = "none")]
pub const DEFAULT_STRING_VECTOR_MAP_LOOKUP_OR_INSERT_OPS: StringVectorMapLookupOrInsertOps = StringVectorMapLookupOrInsertOps {
    vector_initialize: retail_vector_initialize, key_construct: retail_key_construct, query_construct: retail_query_construct,
    tree_lookup_or_insert: retail_tree_lookup_or_insert, query_destroy: retail_query_destroy, string_release: retail_string_release,
    key_destroy: retail_key_destroy, vector_destroy: retail_vector_destroy,
};
#[cfg(not(target_os = "none"))]
pub const DEFAULT_STRING_VECTOR_MAP_LOOKUP_OR_INSERT_OPS: StringVectorMapLookupOrInsertOps = StringVectorMapLookupOrInsertOps {
    vector_initialize: unavailable_void, key_construct: unavailable_key, query_construct: unavailable_query,
    tree_lookup_or_insert: unavailable_lookup, query_destroy: unavailable_destroy, string_release: unavailable_void,
    key_destroy: unavailable_destroy, vector_destroy: unavailable_void,
};
pub static mut STRING_VECTOR_MAP_LOOKUP_OR_INSERT_OPS: StringVectorMapLookupOrInsertOps = DEFAULT_STRING_VECTOR_MAP_LOOKUP_OR_INSERT_OPS;

static EMPTY_KEY_COMPONENT: u32 = 0;

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_vector_map_lookup_or_insert(tree: *mut u8, source: *const u8) -> *mut u8 {
    let ops = unsafe { ptr::read_volatile(ptr::addr_of!(STRING_VECTOR_MAP_LOOKUP_OR_INSERT_OPS)) };
    let mut vector = [0u32; 3];
    let mut key = [0u8; 20];
    let mut query = [0u8; 24];
    let mut result = [0u32; 2];
    unsafe {
        (ops.vector_initialize)(vector.as_mut_ptr().cast());
        (ops.key_construct)(key.as_mut_ptr(), (&raw const EMPTY_KEY_COMPONENT).cast(), (&raw const EMPTY_KEY_COMPONENT).cast(), vector.as_mut_ptr().cast(), 1);
        crate::cxx::string::cxx_string_copy_ctor(query.as_mut_ptr().cast(), source.cast());
        let query_tail = (ops.query_construct)(query.as_mut_ptr().add(4), key.as_ptr());
        (ops.tree_lookup_or_insert)(result.as_mut_ptr(), tree, query_tail.sub(4));
        let destroyed_query = (ops.query_destroy)(query.as_mut_ptr().add(4));
        (ops.string_release)(destroyed_query.sub(4));
        (ops.key_destroy)(key.as_mut_ptr());
        (ops.vector_destroy)(vector.as_mut_ptr().cast());
        (result[0] as usize).wrapping_add(20) as *mut u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 8] = [0; 8];
    static mut COUNT: usize = 0;
    static mut RESULT: u32 = 0;
    unsafe fn event(value: u8) { unsafe { EVENTS[COUNT] = value; COUNT += 1; } }
    unsafe extern "C" fn vector(_: *mut u8) { unsafe { event(1) } }
    unsafe extern "C" fn key(_: *mut u8, _: *const u8, _: *const u8, _: *mut u8, flag: u32) { assert_eq!(flag, 1); unsafe { event(2) } }
    unsafe extern "C" fn query(destination: *mut u8, _: *const u8) -> *mut u8 { unsafe { event(3) }; destination }
    unsafe extern "C" fn lookup(result: *mut u32, _: *mut u8, _: *const u8) { unsafe { event(4); *result = RESULT; } }
    unsafe extern "C" fn destroy(value: *mut u8) -> *mut u8 { unsafe { event(5) }; value }
    unsafe extern "C" fn release(_: *mut u8) { unsafe { event(6) } }
    unsafe extern "C" fn vector_destroy(_: *mut u8) { unsafe { event(8) } }
    #[test]
    fn constructs_queries_and_cleans_up_before_returning_mapped_word() {
        let _lock = LOCK.lock(); unsafe {
            EVENTS = [0; 8]; COUNT = 0; RESULT = 0x1234_5000;
            STRING_VECTOR_MAP_LOOKUP_OR_INSERT_OPS = StringVectorMapLookupOrInsertOps { vector_initialize: vector, key_construct: key, query_construct: query, tree_lookup_or_insert: lookup, query_destroy: destroy, string_release: release, key_destroy: destroy, vector_destroy };
            let input = crate::cxx::string::empty_rep_data();
            assert_eq!(string_vector_map_lookup_or_insert(0x1000usize as *mut u8, (&raw const input).cast()), 0x1234_5014usize as *mut u8);
            assert_eq!(&EVENTS[..COUNT], &[1, 2, 3, 4, 5, 6, 5, 8]);
            STRING_VECTOR_MAP_LOOKUP_OR_INSERT_OPS = DEFAULT_STRING_VECTOR_MAP_LOOKUP_OR_INSERT_OPS;
        }
    }
}
