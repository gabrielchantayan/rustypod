//! libstdc++ RB-tree pool destructor.
//!
//! `rb_tree_pool_destruct` — original: `FUN_082a7f50` @ `0x082a7f50`
//! (136 bytes). Raw ARM words establish the body as
//! `0x082a7f50..0x082a7fd4`; `0x082a7fd8` starts its next sibling. It has
//! three direct, unconditional internal `bl` instructions and no predicated
//! `bl` instructions. The four direct callers are `0x0809dbf8`,
//! `0x0809dc24`, `0x0809df84`, and `0x0809dfb0`.
//!
//! If tree+0x10 has a header, the destructor erases `[header->left, header)`
//! through its type-specific runtime helper at `0x083bcf44`, moves the header
//! to the allocator's tree+0x04 recycle list, then releases every 12-byte
//! chunk record from tree+0x00. Each record's block (+0x08) is released with
//! its capacity (+0x04), followed by the record itself. A null header skips
//! the whole teardown and the input tree is returned.
//!
//! Deliberate deviation: the unported type-specific erase helper has no
//! recovered semantic identity, so the ARM call remains an address seam;
//! host tests inject it directly. Rust keeps one header temporary where ADS
//! spills two iterator words and an erase-result word.

const CHUNKS: usize = 0x00;
const RECYCLED_HEADERS: usize = 0x04;
const HEADER: usize = 0x10;
const HEADER_LEFT: usize = 0x08;
const HEADER_RECYCLE_NEXT: usize = 0x0c;
const CHUNK_NEXT: usize = 0x00;
const CHUNK_CAPACITY: usize = 0x04;
const CHUNK_BLOCK: usize = 0x08;

type EraseRange = unsafe extern "C" fn(*mut u32, *mut u8, *mut u32, *mut u32) -> *mut u32;
type Dealloc = unsafe extern "C" fn(*mut u8, usize, usize);

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe extern "C" fn erase_range(out: *mut u32, tree: *mut u8, first: *mut u32, last: *mut u32) -> *mut u32 {
    let erase: EraseRange = unsafe { core::mem::transmute(0x083b_cf44usize) };
    unsafe { erase(out, tree, first, last) }
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn erase_range(_out: *mut u32, _tree: *mut u8, _first: *mut u32, _last: *mut u32) -> *mut u32 {
    core::ptr::null_mut()
}

/// Destroys a target-layout libstdc++ RB tree and returns `tree`.
///
/// # Safety
/// `tree`, its header, and every chunk record must remain writable/readable
/// through the corresponding erase and deallocation calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.rb_tree_pool_destruct")]
#[inline(never)]
pub unsafe extern "C" fn rb_tree_pool_destruct(tree: *mut u8) -> *mut u8 {
    unsafe { rb_tree_pool_destruct_with(tree, erase_range, crate::heap::veneers::cxx_array_dealloc) }
}

unsafe fn rb_tree_pool_destruct_with(tree: *mut u8, erase: EraseRange, dealloc: Dealloc) -> *mut u8 {
    let mut header = unsafe { tree.add(HEADER).cast::<u32>().read() };
    if header != 0 {
        let mut begin = unsafe { (header as usize as *const u8).add(HEADER_LEFT).cast::<u32>().read() };
        let mut erased = core::mem::MaybeUninit::<u32>::uninit();
        unsafe { erase(erased.as_mut_ptr(), tree, &mut begin, &mut header) };

        let header = unsafe { tree.add(HEADER).cast::<u32>().read() as usize as *mut u8 };
        unsafe {
            header.add(HEADER_RECYCLE_NEXT).cast::<u32>().write(tree.add(RECYCLED_HEADERS).cast::<u32>().read());
            tree.add(RECYCLED_HEADERS).cast::<u32>().write(header as usize as u32);
        }
        loop {
            let chunk = unsafe { tree.add(CHUNKS).cast::<u32>().read() };
            if chunk == 0 {
                break;
            }
            let chunk = chunk as usize as *mut u8;
            unsafe {
                tree.add(CHUNKS).cast::<u32>().write(chunk.add(CHUNK_NEXT).cast::<u32>().read());
                dealloc(chunk.add(CHUNK_BLOCK).cast::<u32>().read() as usize as *mut u8, chunk.add(CHUNK_CAPACITY).cast::<u32>().read() as usize, 0);
                dealloc(chunk, 1, 0);
            }
        }
    }
    tree
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x400;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| crate::testing::try_map_u32_slab(crate::testing::hints::RB_TREE_POOL_DESTRUCT, SLAB_LEN).map(|p| p as usize));
    static LOCK: Mutex<()> = Mutex::new(());
    static ERASE_TREE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static ERASE_FIRST: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static DEALLOC: [std::sync::atomic::AtomicUsize; 4] = [const { std::sync::atomic::AtomicUsize::new(0) }; 4];

    unsafe extern "C" fn recording_erase(_out: *mut u32, tree: *mut u8, first: *mut u32, _last: *mut u32) -> *mut u32 {
        ERASE_TREE.store(tree as usize, std::sync::atomic::Ordering::Relaxed);
        ERASE_FIRST.store(unsafe { first.read() } as usize, std::sync::atomic::Ordering::Relaxed);
        core::ptr::null_mut()
    }
    unsafe extern "C" fn recording_dealloc(ptr: *mut u8, count: usize, elem: usize) {
        let index = DEALLOC[0].fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if index < DEALLOC.len() {
            DEALLOC[index].store((ptr as usize) ^ (count << 4) ^ elem, std::sync::atomic::Ordering::Relaxed);
        }
    }
    unsafe fn word(at: *mut u8, value: u32) { unsafe { at.cast::<u32>().write(value) } }

    #[test]
    fn destroys_chunks_and_recycles_header_after_erasing_range() {
        let _lock = LOCK.lock();
        let Some(slab) = *SLAB else { assert!(crate::testing::note_missing_u32_fixture("app::rb_tree_pool_destruct")); return; };
        unsafe {
            core::ptr::write_bytes(slab as *mut u8, 0, SLAB_LEN);
            let tree = slab as *mut u8;
            let header = tree.add(0x80);
            let first = tree.add(0xa0);
            let chunk1 = tree.add(0xc0);
            let chunk2 = tree.add(0xe0);
            word(tree.add(HEADER), header as usize as u32);
            word(header.add(HEADER_LEFT), first as usize as u32);
            word(tree.add(RECYCLED_HEADERS), 0x1234_5678);
            word(tree.add(CHUNKS), chunk1 as usize as u32);
            word(chunk1.add(CHUNK_NEXT), chunk2 as usize as u32);
            word(chunk1.add(CHUNK_CAPACITY), 7); word(chunk1.add(CHUNK_BLOCK), 0x1111_0000);
            word(chunk2.add(CHUNK_CAPACITY), 9); word(chunk2.add(CHUNK_BLOCK), 0x2222_0000);
            ERASE_TREE.store(0, std::sync::atomic::Ordering::Relaxed); ERASE_FIRST.store(0, std::sync::atomic::Ordering::Relaxed);
            for value in &DEALLOC { value.store(0, std::sync::atomic::Ordering::Relaxed); }
            assert_eq!(rb_tree_pool_destruct_with(tree, recording_erase, recording_dealloc), tree);
            assert_eq!(ERASE_TREE.load(std::sync::atomic::Ordering::Relaxed), tree as usize);
            assert_eq!(ERASE_FIRST.load(std::sync::atomic::Ordering::Relaxed), first as usize);
            assert_eq!(header.add(HEADER_RECYCLE_NEXT).cast::<u32>().read(), 0x1234_5678);
            assert_eq!(tree.add(RECYCLED_HEADERS).cast::<u32>().read(), header as usize as u32);
            assert_eq!(tree.add(CHUNKS).cast::<u32>().read(), 0);
            assert_eq!(DEALLOC[0].load(std::sync::atomic::Ordering::Relaxed), 4);
        }
    }

    #[test]
    fn null_header_skips_erase_and_deallocation() {
        let _lock = LOCK.lock();
        let Some(slab) = *SLAB else { assert!(crate::testing::note_missing_u32_fixture("app::rb_tree_pool_destruct")); return; };
        unsafe {
            core::ptr::write_bytes(slab as *mut u8, 0, SLAB_LEN);
            ERASE_TREE.store(0, std::sync::atomic::Ordering::Relaxed);
            for value in &DEALLOC { value.store(0, std::sync::atomic::Ordering::Relaxed); }
            assert_eq!(rb_tree_pool_destruct_with(slab as *mut u8, recording_erase, recording_dealloc), slab as *mut u8);
            assert_eq!(ERASE_TREE.load(std::sync::atomic::Ordering::Relaxed), 0);
            assert_eq!(DEALLOC[0].load(std::sync::atomic::Ordering::Relaxed), 0);
        }
    }
}
