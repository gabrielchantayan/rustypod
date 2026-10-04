//! Linked entry processing — `FUN_08207560` @ `0x08207560`.
//! True size 140 bytes, ending at the next push boundary `0x082075ec`.
//! Inbound: two plain BLs (0x082073c0, 0x082074fc), zero predicated BLs.
//! Outbound: two plain BLs, zero predicated BLs, one virtual BLX at 0x08207598.
//!
//! Cache owner word 0's word 1, initialize a two-pointer entry once, then walk
//! nodes while vtable slot +8 returns zero. Resolve node index through
//! 0x0814c598 and process the entry through 0x082073d8; propagate either error.
//! A virtual stop returns zero, not its result. Reload next after processing,
//! allowing the processor to change the chain. Both callers build/extend the
//! same output; concrete class identities remain unresolved.
//!
//! Deviations: repr(C) pointer fields expand on hosts, preserving ARM offsets;
//! typed calls replace BL/BLX. Only the virtual method's evidenced receiver
//! argument is modeled. Direct callees remain unported firmware-address seams,
//! with explicit host replacements rather than guessed implementations.

use core::mem::transmute;

#[repr(C)]
pub struct EntryOwnerMetadata {
    pub opaque: u32,
    pub entries: *mut u8,
}
#[repr(C)]
pub struct EntryOwner {
    pub metadata: *const EntryOwnerMetadata,
}
#[repr(C)]
pub struct LinkedEntryNode {
    pub vtable: *const usize,
    pub next: *mut LinkedEntryNode,
    pub index: u32,
}
#[repr(C)]
pub struct ResolvedEntry {
    pub record: *mut u8,
    pub container: *mut u8,
}

pub type ResolveEntry = unsafe extern "C" fn(*mut u8, u32, *mut ResolvedEntry) -> i32;
pub type ProcessEntry = unsafe extern "C" fn(*mut EntryOwner, *mut u8, *mut ResolvedEntry, *mut LinkedEntryNode) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resolver(_: *mut u8, _: u32, _: *mut ResolvedEntry) -> i32 {
    panic!("install linked_entry_process resolver seam for 0x0814c598")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_processor(_: *mut EntryOwner, _: *mut u8, _: *mut ResolvedEntry, _: *mut LinkedEntryNode) -> i32 {
    panic!("install linked_entry_process processor seam for 0x082073d8")
}
#[cfg(not(target_os = "none"))]
pub static mut LINKED_ENTRY_RESOLVE: ResolveEntry = missing_resolver;
#[cfg(not(target_os = "none"))]
pub static mut LINKED_ENTRY_PROCESS: ProcessEntry = missing_processor;

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(EntryOwnerMetadata, entries) == 4);
    assert!(core::mem::offset_of!(LinkedEntryNode, next) == 4);
    assert!(core::mem::offset_of!(LinkedEntryNode, index) == 8);
    assert!(core::mem::size_of::<ResolvedEntry>() == 8);
};

/// # Safety
/// Owner metadata must be valid even for an empty chain. Each visited node's
/// vtable slot 2 and both firmware callees must implement the recovered ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_entry_process(
    owner: *mut EntryOwner, output: *mut u8, mut node: *mut LinkedEntryNode,
) -> i32 {
    let entries = unsafe { (*(*owner).metadata).entries };
    let mut entry = ResolvedEntry { record: core::ptr::null_mut(), container: core::ptr::null_mut() };
    #[cfg(target_os = "none")]
    let resolve: ResolveEntry = unsafe { transmute(0x0814c598usize) };
    #[cfg(target_os = "none")]
    let process: ProcessEntry = unsafe { transmute(0x082073d8usize) };
    while !node.is_null() {
        let stop: unsafe extern "C" fn(*mut LinkedEntryNode) -> i32 =
            unsafe { transmute((*node).vtable.add(2).read()) };
        if unsafe { stop(node) } != 0 { break; }
        #[cfg(not(target_os = "none"))]
        let resolve = unsafe { core::ptr::addr_of!(LINKED_ENTRY_RESOLVE).read_volatile() };
        let result = unsafe { resolve(entries, (*node).index, &mut entry) };
        if result != 0 { return result; }
        #[cfg(not(target_os = "none"))]
        let process = unsafe { core::ptr::addr_of!(LINKED_ENTRY_PROCESS).read_volatile() };
        let result = unsafe { process(owner, output, &mut entry, node) };
        if result != 0 { return result; }
        node = unsafe { (*node).next };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        node: LinkedEntryNode,
        stop: i32,
        resolve_error: i32,
        process_error: i32,
        replacement: *mut LinkedEntryNode,
        visits: u32,
    }
    unsafe extern "C" fn stop(node: *mut LinkedEntryNode) -> i32 {
        unsafe { (*node.cast::<Fixture>()).stop }
    }
    unsafe extern "C" fn resolve(entries: *mut u8, index: u32, entry: *mut ResolvedEntry) -> i32 {
        let fixtures = entries.cast::<Fixture>();
        let fixture = unsafe { &mut *fixtures.add(index as usize) };
        // The processor changes the shared entry; later resolution must see it.
        unsafe { assert_eq!((*entry).record as usize, index as usize); }
        fixture.visits += 1;
        unsafe { (*entry).container = entries; }
        fixture.resolve_error
    }
    unsafe extern "C" fn process(_: *mut EntryOwner, output: *mut u8, entry: *mut ResolvedEntry, node: *mut LinkedEntryNode) -> i32 {
        let fixture = unsafe { &mut *node.cast::<Fixture>() };
        unsafe {
            assert_eq!((*entry).container, output);
            (*entry).record = (fixture.node.index as usize + 1) as *mut u8;
        }
        fixture.visits += 10;
        fixture.node.next = fixture.replacement;
        fixture.process_error
    }

    #[test]
    fn empty_stop_errors_and_mutated_chain() {
        unsafe {
            LINKED_ENTRY_RESOLVE = resolve;
            LINKED_ENTRY_PROCESS = process;
        }
        let table = [0, 0, stop as *const () as usize];
        let mut fixtures: [Fixture; 3] = core::array::from_fn(|index| Fixture {
            node: LinkedEntryNode { vtable: table.as_ptr(), next: core::ptr::null_mut(), index: index as u32 },
            stop: 0, resolve_error: 0, process_error: 0, replacement: core::ptr::null_mut(), visits: 0,
        });
        let entries = fixtures.as_mut_ptr().cast::<u8>();
        let metadata = EntryOwnerMetadata { opaque: 0, entries };
        let mut owner = EntryOwner { metadata: &metadata };
        assert_eq!(unsafe { linked_entry_process(&mut owner, entries, core::ptr::null_mut()) }, 0);
        for (stop_value, resolve_error, process_error, expected, visits) in [
            (7, 0, 0, 0, 0), (0, -9, 0, -9, 1), (0, 0, 23, 23, 11),
        ] {
            fixtures[0].stop = stop_value;
            fixtures[0].resolve_error = resolve_error;
            fixtures[0].process_error = process_error;
            fixtures[0].visits = 0;
            fixtures[0].node.next = core::ptr::without_provenance_mut(1);
            assert_eq!(unsafe { linked_entry_process(&mut owner, entries, &mut fixtures[0].node) }, expected);
            assert_eq!(fixtures[0].visits, visits);
        }
        for index in 0..3 {
            fixtures[index].stop = 0;
            fixtures[index].resolve_error = 0;
            fixtures[index].process_error = 0;
            fixtures[index].visits = 0;
            fixtures[index].node.next = core::ptr::without_provenance_mut(1);
            fixtures[index].replacement = if index == 2 { core::ptr::null_mut() } else { &mut fixtures[index + 1].node };
        }
        assert_eq!(unsafe { linked_entry_process(&mut owner, entries, &mut fixtures[0].node) }, 0);
        assert_eq!(fixtures.map(|fixture| fixture.visits), [11, 11, 11]);
        unsafe {
            LINKED_ENTRY_RESOLVE = missing_resolver;
            LINKED_ENTRY_PROCESS = missing_processor;
        }
    }
}
