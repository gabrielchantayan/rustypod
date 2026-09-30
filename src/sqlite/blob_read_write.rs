//! Incremental SQLite blob I/O — `FUN_082b79dc` @ `0x082b79dc`.
//!
//! Raw A32 establishes 164 bytes, ending with the API-exit tail branch at
//! `0x082b7a7c`, before the next prologue at `0x082b7a80`. Whole-image word
//! decoding finds two inbound plain BL calls (`0x0838f69c`, `0x0838f6bc`),
//! no predicated callers; the body has three plain BL, no predicated BL,
//! one callback BLX, and a tail B to `sqlite_api_exit`.
//!
//! SQLite's private blobReadWrite: reject a signed, wrapping offset+length
//! beyond the blob size; return ABORT for an expired statement; otherwise
//! enter the cursor's Btree, transfer at the blob-relative payload offset,
//! and leave. ABORT finalizes and clears the statement; other results update
//! the database and statement error words. Finish through sqlite3ApiExit.
//! Deliberate deviations: none. Pointer words retain the target's 32-bit
//! layout on hosts; dependencies call the existing Rust ports directly.

use super::api_exit::sqlite_api_exit;
use super::btree_lock::{btree_enter, btree_leave};
use super::finalize::sqlite_vdbe_finalize;

/// Firmware Incrblob layout. All pointer fields are target-width words.
#[repr(C)]
pub struct IncrementalBlob {
    pub writable: i32,
    pub byte_count: i32,
    pub payload_offset: i32,
    pub cursor: u32,
    pub statement: u32,
    pub database: u32,
}

pub type BlobTransfer = unsafe extern "C" fn(*mut u8, i32, i32, *mut u8) -> i32;

/// Transfer bytes through an incremental blob's cursor.
///
/// # Safety
/// `blob` and its target-width pointers must describe live firmware objects.
/// `transfer` must accept the cursor, wrapping payload offset, signed length,
/// and buffer, and return a SQLite result code. Non-ABORT transfers require
/// a non-NULL database. The statement must satisfy the VDBE finalizer contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn blob_read_write(
    blob: *mut IncrementalBlob,
    buffer: *mut u8,
    length: i32,
    offset: i32,
    transfer: BlobTransfer,
) -> i32 {
    let database = (*blob).database as usize as *mut u8;
    if offset.wrapping_add(length) > (*blob).byte_count {
        return 1;
    }
    let statement = (*blob).statement as usize as *mut super::vdbe::Vdbe;
    let result = if statement.is_null() {
        4
    } else {
        let cursor = (*blob).cursor as usize as *mut u8;
        btree_enter(cursor.cast::<u32>().read() as usize as *mut u8);
        let result = transfer(cursor, (*blob).payload_offset.wrapping_add(offset), length, buffer);
        // Reload the cursor and Btree after the callback, just as retail does.
        let cursor = (*blob).cursor as usize as *mut u8;
        btree_leave(cursor.cast::<u32>().read() as usize as *mut u8);
        if result == 4 {
            sqlite_vdbe_finalize(statement);
            (*blob).statement = 0;
        } else {
            database.add(0x14).cast::<i32>().write(result);
            // Retail Vdbe.rc is a word at +0x74, not a host-native field offset.
            statement.cast::<u8>().add(0x74).cast::<i32>().write(result);
        }
        result
    };
    sqlite_api_exit(database, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn transfer(cursor: *mut u8, offset: i32, length: i32, buffer: *mut u8) -> i32 {
        let btree = cursor.cast::<u32>().read() as usize as *mut u8;
        assert_eq!(btree.add(0x0c).cast::<i32>().read(), 1);
        assert_eq!(offset, cursor.add(4).cast::<i32>().read());
        assert_eq!(length, cursor.add(8).cast::<i32>().read());
        for index in 0..length {
            buffer.add(index as usize).write((offset.wrapping_add(index)) as u8);
        }
        cursor.add(12).cast::<i32>().read()
    }

    #[test]
    fn boundaries_status_propagation_and_expiration() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::SQLITE_BLOB_READ_WRITE, 0x4000,
        ) else { return; };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x4000);
            let cursor = slab;
            let btree = slab.add(0x100);
            let database = slab.add(0x200);
            let statement = slab.add(0x400);
            cursor.cast::<u32>().write(btree as u32);
            btree.add(9).write(1); // Btree.sharable
            database.add(0x18).cast::<i32>().write(0xff);
            let mut blob = IncrementalBlob {
                writable: 0, byte_count: 8, payload_offset: 100,
                cursor: cursor as u32, statement: statement as u32,
                database: database as u32,
            };
            let mut buffer = [0xa5; 10];
            // Oversized range bypasses transfer, status updates, and API masking.
            database.add(0x18).cast::<i32>().write(0);
            assert_eq!(blob_read_write(&mut blob, buffer.as_mut_ptr(), 1, 8, transfer), 1);
            assert_eq!(buffer, [0xa5; 10]);
            assert_eq!(blob.statement, statement as u32);
            database.add(0x18).cast::<i32>().write(0xff);
            for (length, offset, result) in [(8, 0, 0), (0, 8, 0x123), (2, -1, 11), (0, i32::MIN, 0)] {
                cursor.add(4).cast::<i32>().write(100i32.wrapping_add(offset));
                cursor.add(8).cast::<i32>().write(length);
                cursor.add(12).cast::<i32>().write(result);
                buffer.fill(0xa5);
                assert_eq!(blob_read_write(&mut blob, buffer.as_mut_ptr(), length, offset, transfer), result & 0xff);
                for index in 0..length as usize {
                    assert_eq!(buffer[index], (100i32.wrapping_add(offset).wrapping_add(index as i32)) as u8);
                }
                assert!(buffer[length as usize..].iter().all(|byte| *byte == 0xa5));
                assert_eq!(database.add(0x14).cast::<i32>().read(), result);
                assert_eq!(statement.add(0x74).cast::<i32>().read(), result);
                assert_eq!(btree.add(0x0c).cast::<i32>().read(), 0);
            }
            // Signed addition wraps before the range comparison; negative lengths
            // are forwarded rather than rejected by a stronger host-side guard.
            cursor.add(4).cast::<i32>().write(100i32.wrapping_add(i32::MAX));
            cursor.add(8).cast::<i32>().write(1);
            cursor.add(12).cast::<i32>().write(0);
            assert_eq!(blob_read_write(&mut blob, buffer.as_mut_ptr(), 1, i32::MAX, transfer), 0);
            cursor.add(4).cast::<i32>().write(100);
            cursor.add(8).cast::<i32>().write(-1);
            assert_eq!(blob_read_write(&mut blob, buffer.as_mut_ptr(), -1, 0, transfer), 0);
            // Invalid VDBE magic returns MISUSE from the real finalizer without
            // deleting this fixture. Its result is ignored by the blob helper.
            cursor.add(8).cast::<i32>().write(0);
            cursor.add(12).cast::<i32>().write(4);
            database.add(0x14).cast::<i32>().write(17);
            statement.add(0x74).cast::<i32>().write(19);
            assert_eq!(blob_read_write(&mut blob, buffer.as_mut_ptr(), 0, 0, transfer), 4);
            assert_eq!(blob.statement, 0);
            assert_eq!(database.add(0x14).cast::<i32>().read(), 17);
            assert_eq!(statement.add(0x74).cast::<i32>().read(), 19);
            // An expired statement must not dereference a stale cursor.
            blob.cursor = 0;
            blob.database = 0;
            assert_eq!(blob_read_write(&mut blob, buffer.as_mut_ptr(), 0, 0, transfer), 4);
            assert_eq!(blob_read_write(&mut blob, buffer.as_mut_ptr(), 9, 0, transfer), 1);
        }
    }
}
