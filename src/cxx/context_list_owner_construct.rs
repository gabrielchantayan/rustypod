//! Context/list owner constructor — `FUN_0818b32c` @ **0x0818b32c**.
//! True extent: 200 bytes (196 code + four-byte vtable literal); next real
//! function starts at 0x0818b3f4. Seven outbound plain BLs, zero predicated
//! BLs; two inbound plain BLs, zero predicated BLs (whole-image word decode).
//!
//! Seeds the intrusive owner links, clears the embedded node pool, acquires
//! a single-node circular sentinel, then constructs a 30-element context
//! array, recursive mutex, two normal mutexes, and opaque context. Stores
//! the client word, -1 index, empty trailing pair/flag, and owner backlink.
//! Returns this, as raw r0 and both allocation callers require.
//! Deviations: unused mutexattr register seeds are zeroed; existing Rust
//! constructor seams are reused. The unported trailing pair/flag initializer
//! at 0x082081e4 is called at its verified address on target and modeled
//! exactly on host. Pointer fields are target-width words, not host pointers.

use super::list_node_pool_acquire_083dd1a8::list_node_pool_acquire_083dd1a8;
use super::mutex::cxx_mutex_construct;
use super::recursive_mutex::cxx_recursive_mutex_construct;
use super::opaque_context_array_construct::opaque_context_array_construct;
use super::opaque_context_initialize::initialize_opaque_context;

unsafe fn seed_owner(this: *mut u32, owner_word: u32) {
    this.write(0x0898_9990);
    this.add(2).write(this.add(1) as usize as u32);
    this.add(1).write(owner_word);
    this.add(3).write(this.add(1) as usize as u32);
    for word in 5..12 { this.add(word).write(0); }
}

unsafe fn link_sentinel(this: *mut u32, sentinel: *mut u32) {
    this.add(10).write(sentinel as usize as u32);
    sentinel.write(sentinel as usize as u32);
    sentinel.add(1).write(sentinel as usize as u32);
    this.add(12).write(0);
    this.add(13).write(0);
    this.add(14).cast::<u8>().write(0);
}

#[cfg(target_os = "none")]
unsafe fn construct_pair(this: *mut u8) -> *mut u8 {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8) -> *mut u8>(0x0820_81e4)(this)
}
#[cfg(not(target_os = "none"))]
unsafe fn construct_pair(this: *mut u8) -> *mut u8 {
    this.cast::<u32>().write(0);
    this.add(4).cast::<u32>().write(0);
    this.add(8).write(0);
    this
}

unsafe fn finish_owner(context: *mut u8, client_word: u32) -> *mut u32 {
    context.add(0x1c).cast::<u32>().write(client_word);
    context.add(0x20).cast::<u32>().write(u32::MAX);
    context.add(0x24).cast::<u32>().write(0);
    let pair = construct_pair(context.add(0x28));
    let owner = pair.sub(0x1c4).cast::<u32>();
    owner.add(0x1d0 / 4).write(0);
    owner.add(0x1c8 / 4).write(owner as usize as u32);
    owner
}

/// # Safety
/// `this` must identify 0x1d4 aligned writable bytes; retailOS allocation
/// and embedded constructor contracts must hold. No NULL or failure guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_list_owner_construct(this: *mut u32, owner_word: u32, client_word: u32) -> *mut u32 {
    seed_owner(this, owner_word);
    let sentinel = list_node_pool_acquire_083dd1a8(this.add(6).cast(), 1);
    link_sentinel(this, sentinel.cast());
    let array = opaque_context_array_construct(this.add(15).cast(), 30);
    let recursive = cxx_recursive_mutex_construct(array.add(0x10c), 0, 0, 0);
    let first = cxx_mutex_construct(recursive.add(0x1c), 0, 0, 0);
    let second = cxx_mutex_construct(first.add(0x1c), 0, 0, 0);
    let context = initialize_opaque_context(second.add(0x1c).cast());
    finish_owner(context.cast(), client_word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_storage_becomes_empty_owner_without_clobbering_padding() {
        unsafe {
            for (owner_word, client_word) in [(0, 0), (u32::MAX, 0x8000_0000)] {
                let mut storage = [0xa5a5_a5a5u32; 0x1d4 / 4];
                let this = storage.as_mut_ptr();
                let mut sentinel = [0xdead_beefu32; 3];
                seed_owner(this, owner_word);
                assert_eq!(&storage[5..12], &[0; 7]);
                link_sentinel(this, sentinel.as_mut_ptr());
                assert_eq!(finish_owner(this.cast::<u8>().add(0x19c), client_word), this);
                assert_eq!(storage[0], 0x0898_9990);
                assert_eq!(storage[1], owner_word);
                assert_eq!(storage[2], this.add(1) as usize as u32);
                assert_eq!(storage[3], storage[2]);
                assert_eq!(storage[4], 0xa5a5_a5a5);
                assert_eq!(storage[10], sentinel.as_ptr() as usize as u32);
                assert_eq!(&sentinel[..2], &[storage[10]; 2]);
                assert_eq!(sentinel[2], 0xdead_beef);
                assert_eq!(&storage[12..14], &[0, 0]);
                assert_eq!(storage[14].to_le_bytes(), [0, 0xa5, 0xa5, 0xa5]);
                assert_eq!(&storage[0x1b8 / 4..0x1c8 / 4], &[client_word, u32::MAX, 0, 0]);
                assert_eq!(storage[0x1c8 / 4], this as usize as u32);
                assert_eq!(storage[0x1cc / 4].to_le_bytes(), [0, 0xa5, 0xa5, 0xa5]);
                assert_eq!(storage[0x1d0 / 4], 0);
                assert!(storage[15..0x1b8 / 4].iter().all(|&word| word == 0xa5a5_a5a5));
            }
        }
    }
}
