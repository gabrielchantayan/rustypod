//! Chunked opaque-interface transfer port.
//!
//! Original retailOS: `FUN_0818d774` at `0x0818d774`, 152 bytes
//! (`0x0818d774..0x0818d80c`). Raw words establish two outgoing indirect
//! `blx` calls and no predicated call; a full-image decode finds three inbound
//! unconditional `bl` sites and no predicated inbound calls.
//!
//! Obtains the interface's transfer stride from vtable slot `+0x2c`, then
//! submits no more than 32 units at a time through slot `+0x08`. On each
//! successful submission it advances the logical unit index, the output count,
//! and the source pointer by `stride * chunk_len`; a failed submission stops
//! immediately. Deliberate deviation: host fixtures use native-width vtable
//! pointers, while the target reads the firmware's 32-bit pointer words.

const INTERFACE_OFFSET: usize = 0x478;
const TRANSFER_SLOT: usize = 0x08 / 4;
const STRIDE_SLOT: usize = 0x2c / 4;
const MAX_CHUNK_UNITS: u32 = 32;

type TransferChunk = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32) -> u32;
type TransferStride = unsafe extern "C" fn() -> u32;

#[cfg(target_os = "none")]
unsafe fn transfer_interface(context: *mut u8) -> *const u32 {
    unsafe { (context.add(INTERFACE_OFFSET) as *const u32).read_volatile() as usize as *const u32 }
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostTransferInterface {
    vtable: *const HostTransferVtable,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostTransferVtable {
    unused_00_04: [usize; TRANSFER_SLOT],
    transfer_chunk: TransferChunk,
    unused_0c_28: [usize; STRIDE_SLOT - TRANSFER_SLOT - 1],
    transfer_stride: TransferStride,
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn chunked_interface_transfer(
    context: *mut u8,
    mut unit_index: u32,
    mut source: *mut u8,
    mut remaining_units: u32,
    transferred_units: *mut u32,
) -> u32 {
    #[cfg(target_os = "none")]
    let (transfer_chunk, transfer_stride, interface) = unsafe {
        let interface = transfer_interface(context);
        (
            core::mem::transmute::<usize, TransferChunk>(interface.add(TRANSFER_SLOT).read_volatile() as usize),
            core::mem::transmute::<usize, TransferStride>(interface.add(STRIDE_SLOT).read_volatile() as usize),
            interface as *mut u8,
        )
    };
    #[cfg(not(target_os = "none"))]
    let (transfer_chunk, transfer_stride, interface) = unsafe {
        let interface = &*((context.add(INTERFACE_OFFSET) as *const *const HostTransferInterface).read());
        ((*interface.vtable).transfer_chunk, (*interface.vtable).transfer_stride, interface as *const _ as *mut u8)
    };

    let stride = unsafe { transfer_stride() };
    while remaining_units != 0 {
        let chunk_units = if remaining_units > MAX_CHUNK_UNITS { MAX_CHUNK_UNITS } else { remaining_units };
        if unsafe { transfer_chunk(interface, unit_index, source, chunk_units, 0) } != 0 {
            return 0;
        }
        unit_index += chunk_units;
        remaining_units -= chunk_units;
        unsafe { transferred_units.write(transferred_units.read() + chunk_units) };
        source = unsafe { source.add((stride * chunk_units) as usize) };
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct TestInterface {
        interface: HostTransferInterface,
        calls: usize,
        fail_at: usize,
        indices: [u32; 3],
        lengths: [u32; 3],
        sources: [usize; 3],
    }

    unsafe extern "C" fn stride() -> u32 { 3 }
    unsafe extern "C" fn submit(interface: *mut u8, index: u32, source: *mut u8, len: u32, _: u32) -> u32 {
        let state = unsafe { &mut *interface.cast::<TestInterface>() };
        let call = state.calls;
        state.indices[call] = index;
        state.lengths[call] = len;
        state.sources[call] = source as usize;
        state.calls += 1;
        u32::from(call == state.fail_at)
    }

    static VTABLE: HostTransferVtable = HostTransferVtable {
        unused_00_04: [0; TRANSFER_SLOT], transfer_chunk: submit,
        unused_0c_28: [0; STRIDE_SLOT - TRANSFER_SLOT - 1], transfer_stride: stride,
    };

    fn run(units: u32, fail_at: usize) -> (u32, u32, TestInterface, [u8; 200]) {
        let mut interface = TestInterface {
            interface: HostTransferInterface { vtable: &VTABLE }, calls: 0, fail_at,
            indices: [0; 3], lengths: [0; 3], sources: [0; 3],
        };
        let mut context = [0u8; INTERFACE_OFFSET + core::mem::size_of::<usize>()];
        unsafe { (context.as_mut_ptr().add(INTERFACE_OFFSET) as *mut *const HostTransferInterface).write(&interface.interface) };
        let mut source = [0u8; 200];
        let mut total = 7;
        let result = unsafe { chunked_interface_transfer(context.as_mut_ptr(), 11, source.as_mut_ptr(), units, &mut total) };
        (result, total, interface, source)
    }

    #[test]
    fn chunks_at_thirty_two_and_advances_by_stride() {
        let (result, total, interface, _) = run(65, usize::MAX);
        assert_eq!((result, total, interface.calls), (1, 72, 3));
        assert_eq!(interface.indices, [11, 43, 75]);
        assert_eq!(interface.lengths, [32, 32, 1]);
        assert_eq!([interface.sources[1] - interface.sources[0], interface.sources[2] - interface.sources[1]], [96, 96]);
    }

    #[test]
    fn failure_preserves_the_failed_chunk_progress() {
        let (result, total, interface, _) = run(40, 1);
        assert_eq!((result, total, interface.calls), (0, 39, 2));
    }

    #[test]
    fn zero_units_does_not_submit() {
        let (result, total, interface, _) = run(0, usize::MAX);
        assert_eq!((result, total, interface.calls), (1, 7, 0));
    }
}
