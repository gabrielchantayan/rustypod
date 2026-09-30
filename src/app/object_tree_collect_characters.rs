use crate::app::registry::{object_cast_to_class, FrameworkObject};
use crate::cxx::bit_set::{bit_set_insert_utf8, BitSet};
use crate::cxx::string_object::{string_object_c_str, StringObject};
#[cfg(target_os = "none")]
use crate::cxx::templates::container_element_at_veneer_9cef0;
#[cfg(not(target_os = "none"))]
use crate::cxx::templates::container_element_at_alias_5f74;

#[repr(C)]
pub struct CharacterTreeVtable {
    pub unresolved: [usize; 5],
    pub cast_to_class: unsafe extern "C" fn(*mut FrameworkObject, u32) -> *mut u8,
    pub kind: unsafe extern "C" fn(*mut CharacterTree) -> i32,
    pub text: unsafe extern "C" fn(*mut CharacterTree) -> *const StringObject,
}

#[repr(C)]
pub struct CharacterChildren {
    pub vtable: *const usize,
    pub count: i32,
}

#[repr(C)]
pub struct CharacterTree {
    pub vtable: *const CharacterTreeVtable,
    pub unresolved: [u32; 8],
    pub children: CharacterChildren,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x24] = [(); core::mem::offset_of!(CharacterTree, children)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0x28] = [(); core::mem::offset_of!(CharacterTree, children)
    + core::mem::offset_of!(CharacterChildren, count)];

/// object_tree_collect_characters — FUN_082a6984 @ 0x082a6984.
/// True extent: 196 bytes, next real function @ 0x082a6a48 (`mov r0,#0x5800;
/// bx lr`). Raw-word scan: two inbound plain BLs (0x082a6954, 0x082a6a10),
/// zero predicated BLs; seven outgoing plain BLs and three virtual BLX sites.
///
/// Insert this node's text into the character bitset, snapshot its signed
/// child count, then visit children in order. Kind exactly 1 is cast to class
/// 0x4b00 and recursively visited; all other kinds contribute only their text.
/// Signed depth > 32 returns before touching any pointer. The context argument
/// is carried through recursion but never read. No NULL guards are added.
///
/// Deliberate deviation: host layouts use native pointers; the host calls the
/// already ported container body on the modeled embedded field rather than
/// applying the target veneer's literal +0x24. Target uses the original veneer.
///
/// # Safety
/// At depth <= 32, nodes, virtual methods, returned strings and indexed child
/// slots must be valid, including cast results that recursion will dereference.
/// The bitset must cover all decoded codepoints. Virtual methods must preserve
/// the live objects and the snapshotted child range during traversal.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_tree_collect_characters(
    context: *mut u8,
    node: *mut CharacterTree,
    set: *mut BitSet,
    depth: i32,
) {
    if depth > 32 {
        return;
    }
    let text = ((*(*node).vtable).text)(node);
    bit_set_insert_utf8(set, string_object_c_str(text));
    let count = (*node).children.count;
    let mut index = 0i32;
    while index < count {
        #[cfg(target_os = "none")]
        let child = container_element_at_veneer_9cef0(node.cast(), index as usize)
            .cast::<CharacterTree>();
        #[cfg(not(target_os = "none"))]
        let child = container_element_at_alias_5f74(
            core::ptr::addr_of_mut!((*node).children).cast(), index as usize,
        ).cast::<CharacterTree>();
        if ((*(*child).vtable).kind)(child) == 1 {
            let subtree = object_cast_to_class(child.cast(), 0x4b00).cast();
            object_tree_collect_characters(context, subtree, set, depth.wrapping_add(1));
        } else {
            let text = ((*(*child).vtable).text)(child);
            bit_set_insert_utf8(set, string_object_c_str(text));
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    use std::{boxed::Box, sync::LazyLock, vec::Vec};

    static LOCK: Mutex<()> = Mutex::new(());
    static WORDS: LazyLock<usize> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::OBJECT_TREE_CHARACTERS, 4096)
            .expect("character bitset fixture") as usize
    });

    #[repr(C)]
    struct Fixture {
        node: CharacterTree,
        entries: Vec<*mut CharacterTree>,
        kind: i32,
        text: StringObject,
        visits: u32,
    }

    unsafe extern "C" fn cast(node: *mut FrameworkObject, id: u32) -> *mut u8 {
        assert_eq!(id, 0x4b00);
        node.cast()
    }
    unsafe extern "C" fn kind(node: *mut CharacterTree) -> i32 {
        (*(node as *mut Fixture)).kind
    }
    unsafe extern "C" fn text(node: *mut CharacterTree) -> *const StringObject {
        let fixture = &mut *(node as *mut Fixture);
        fixture.visits += 1;
        &fixture.text
    }
    unsafe extern "C" fn slot(children: *mut u8, index: usize) -> *mut *mut u8 {
        let fixture = children.sub(core::mem::offset_of!(CharacterTree, children))
            as *mut Fixture;
        (*fixture).entries.as_mut_ptr().add(index).cast()
    }
    static VTABLE: CharacterTreeVtable = CharacterTreeVtable {
        unresolved: [0; 5], cast_to_class: cast, kind, text,
    };
    static CHILD_VTABLE: LazyLock<[usize; 17]> = LazyLock::new(|| {
        let mut slots = [0; 17];
        slots[16] = slot as usize;
        slots
    });
    fn fixture(kind: i32, text: &'static [u8]) -> Box<Fixture> {
        Box::new(Fixture {
            node: CharacterTree {
                vtable: &VTABLE, unresolved: [0; 8],
                children: CharacterChildren { vtable: CHILD_VTABLE.as_ptr(), count: 0 },
            },
            entries: Vec::new(), kind,
            text: StringObject { vtable: core::ptr::null(), payload: text.as_ptr() as *mut u8 },
            visits: 0,
        })
    }
    fn set() -> BitSet {
        unsafe { core::ptr::write_bytes(*WORDS as *mut u8, 0, 4096); }
        BitSet { bit_capacity: 32768, cardinality: 0, words: *WORDS as u32,
            heap_tag: 0x3a, reserved: [0; 3] }
    }
    fn characters(expected: &[u32], set: &BitSet) {
        assert_eq!(set.cardinality, expected.len() as u32);
        for codepoint in 0..32768u32 {
            let word = unsafe { (*WORDS as *const u32).add((codepoint / 32) as usize).read() };
            assert_eq!(word & (1 << (codepoint % 32)) != 0, expected.contains(&codepoint),
                "codepoint {codepoint}");
        }
    }

    #[test]
    fn nested_text_union_and_exact_kind_discriminator() {
        let _guard = LOCK.lock();
        let mut root = fixture(1, b"aba\0");
        let mut subtree = fixture(1, b"\xc3\xa9\0");
        let mut leaf = fixture(2, b"z\0");
        let mut grandchild = fixture(0, b"b\0");
        let mut ignored = fixture(0, b"x\0");
        subtree.entries.push(&mut grandchild.node);
        subtree.node.children.count = 1;
        leaf.entries.push(&mut ignored.node);
        leaf.node.children.count = 1;
        root.entries.extend([&mut subtree.node as *mut _, &mut leaf.node as *mut _]);
        root.node.children.count = 2;
        let mut bits = set();
        unsafe { object_tree_collect_characters(core::ptr::null_mut(), &mut root.node, &mut bits, 0); }
        characters(&[97, 98, 122, 233], &bits);
        assert_eq!(ignored.visits, 0);
        assert_eq!(grandchild.visits, 1);
    }

    #[test]
    fn signed_counts_and_depth_guard() {
        let _guard = LOCK.lock();
        let mut root = fixture(1, b"r\0");
        root.node.children.count = -1;
        let mut bits = set();
        unsafe {
            object_tree_collect_characters(core::ptr::null_mut(), core::ptr::null_mut(),
                core::ptr::null_mut(), 33);
            object_tree_collect_characters(core::ptr::null_mut(), &mut root.node, &mut bits, -1);
        }
        characters(&[114], &bits);
        assert_eq!(root.visits, 1);
    }

    #[test]
    fn cycle_stops_after_depth_32_but_leaf_at_limit_is_included() {
        let _guard = LOCK.lock();
        let mut root = fixture(1, b"r\0");
        let mut leaf = fixture(-1, b"l\0");
        root.entries.extend([&mut root.node as *mut _, &mut leaf.node as *mut _]);
        root.node.children.count = 2;
        let mut bits = set();
        unsafe { object_tree_collect_characters(core::ptr::null_mut(), &mut root.node, &mut bits, 0); }
        characters(&[108, 114], &bits);
        assert_eq!(root.visits, 33);
        assert_eq!(leaf.visits, 33);
    }
}
