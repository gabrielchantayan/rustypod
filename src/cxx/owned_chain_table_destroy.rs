//! `owned_chain_table_destroy` — original: `FUN_0826f3a8` @ `0x0826f3a8`
//! (20 bytes; 4 verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM words `e92d4010 e2800010 eb059095 e2400010 e8bd8010` establish the
//! exact 20-byte extent `0x0826f3a8..0x0826f3bc`: `0x0826f3bc` begins the
//! independent next function with `push {r4, lr}`. The wrapper advances its
//! owner pointer to the embedded chain-table descriptor at +0x10, invokes the
//! unresolved retail table destructor at `0x083d360c`, then returns the
//! original owner pointer. One direct outbound `bl` is unconditional; no
//! predicated direct calls occur. Four inbound direct calls are plain,
//! unconditional `bl` at `0x08269b80`, `0x08269c34`, `0x0826a670`, and
//! `0x0826a758`.
//!
//! # Deliberate deviation
//!
//! `FUN_083d360c` has no established semantic identity or Rust port in
//! `names.yaml`. The target invokes that exact stock entry through a narrowly
//! scoped ABI seam; host tests substitute it to observe the proven +0x10
//! argument and returned owner address.

/// Byte offset of the owned chain-table descriptor in its enclosing owner.
const CHAIN_TABLE_OFFSET: usize = 0x10;
const RETAIL_CHAIN_TABLE_DESTROY: usize = 0x083d360c;

type ChainTableDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe extern "C" fn retail_chain_table_destroy(table: *mut u8) -> *mut u8 {
    let destroy: ChainTableDestroy = unsafe { core::mem::transmute(RETAIL_CHAIN_TABLE_DESTROY) };
    unsafe { destroy(table) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_chain_table_destroy(table: *mut u8) -> *mut u8 {
    table
}

/// Destroys the chain-table descriptor embedded at owner +0x10 and returns
/// `owner`. `owner` must designate at least 0x10 bytes of writable object
/// storage followed by a descriptor accepted by the retail destructor.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.owned_chain_table_destroy")]
#[inline(never)]
pub unsafe extern "C" fn owned_chain_table_destroy(owner: *mut u8) -> *mut u8 {
    unsafe { owned_chain_table_destroy_with(owner, retail_chain_table_destroy) }
}

#[inline(always)]
unsafe fn owned_chain_table_destroy_with(owner: *mut u8, destroy: ChainTableDestroy) -> *mut u8 {
    unsafe { destroy(owner.add(CHAIN_TABLE_OFFSET)) };
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{owned_chain_table_destroy_with, ChainTableDestroy, CHAIN_TABLE_OFFSET};

    static DESTROY_ARGUMENT: AtomicUsize = AtomicUsize::new(0);
    static DESTROY_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_destroy(table: *mut u8) -> *mut u8 {
        DESTROY_ARGUMENT.store(table as usize, Ordering::SeqCst);
        DESTROY_CALLS.fetch_add(1, Ordering::SeqCst);
        table
    }

    #[test]
    fn invokes_the_embedded_descriptor_and_returns_the_owner() {
        let mut owner = [0_u8; CHAIN_TABLE_OFFSET + 16];
        let owner_ptr = owner.as_mut_ptr();
        DESTROY_ARGUMENT.store(0, Ordering::SeqCst);
        DESTROY_CALLS.store(0, Ordering::SeqCst);

        let returned = unsafe {
            owned_chain_table_destroy_with(owner_ptr, record_destroy as ChainTableDestroy)
        };

        assert_eq!(returned, owner_ptr);
        assert_eq!(DESTROY_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(DESTROY_ARGUMENT.load(Ordering::SeqCst), unsafe {
            owner_ptr.add(CHAIN_TABLE_OFFSET) as usize
        });
    }
}
