//! Appending one expression to a SQLite expression list.
//!
//! - `expr_list_append` — original: `FUN_0837857c` @ 0x0837857c
//!   (208 bytes; 18 `bl` call sites, binary-scanned: 17 unconditional
//!   `bl`, one `blne` @ 0x0839ab20, and no tail `b` callers). SQLite
//!   3.5.x's `sqlite3ExprListAppend`.
//!
//! The confirmed body ends at 0x0837864c, where the separately linked
//! `FUN_0837864c` begins. A NULL list allocates its zeroed 0x10-byte header.
//! A full list grows from `n_alloc` to `n_alloc * 2 + 4`, reallocating a
//! 12-byte-stride item array. Allocation failure deletes the incoming
//! expression first, then the partially built list, and returns NULL. When
//! either `expr` or `name` is non-NULL, the new item is zeroed, its name is
//! duplicated through `name_from_token`, and its expression pointer is set.
//! Both NULL leaves the list unchanged.
//!
//! Deliberate deviation: `ExprList` and `ExprListItem` are shared typed
//! `#[repr(C)]` layouts. Their pointer fields widen on the 64-bit host, while
//! 32-bit assertions pin the original 0x10-byte header and 0x0c-byte item
//! layouts. The target still requests and writes the original byte sizes.

use super::expr_delete::expr_delete;
use super::expr_list_delete::{expr_list_delete, ExprList, ExprListItem};
use super::mem::{db_malloc_zero, db_realloc};
use super::name_from_token::name_from_token;

/// expr_list_append — original: `FUN_0837857c` @ 0x0837857c (208 bytes;
/// 18 `bl` call sites, 17 unconditional and one `blne`).
///
/// `sqlite3ExprListAppend`: load `db` from `parse`, then create or grow
/// `list` and append the supplied expression and/or token name. An initial
/// allocation or resize failure consumes `expr`, deletes `list`, and returns
/// NULL. `expr == NULL` and `name == NULL` is a strict no-op after any
/// necessary list allocation or capacity check. Register usage: r0 = parse
/// (whose +0x00 word is db), r4 = list, r6 = expr, r7 = name.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_list_append(
    parse: *mut u8,
    mut list: *mut ExprList,
    expr: *mut u8,
    name: *const u8,
) -> *mut ExprList {
    let db = *(parse as *const *mut u8);
    if list.is_null() {
        list = db_malloc_zero(db, 0x10).cast();
        if list.is_null() {
            expr_delete(expr);
            expr_list_delete(list.cast());
            return core::ptr::null_mut();
        }
    }

    if (*list).n_alloc <= (*list).n_expr {
        let n_alloc = (*list).n_alloc.wrapping_mul(2).wrapping_add(4);
        let items = db_realloc(db, (*list).items.cast(), n_alloc.wrapping_mul(0x0c))
            .cast::<ExprListItem>();
        if items.is_null() {
            expr_delete(expr);
            expr_list_delete(list.cast());
            return core::ptr::null_mut();
        }
        (*list).items = items;
        (*list).n_alloc = n_alloc;
    }

    if !expr.is_null() || !name.is_null() {
        let index = (*list).n_expr;
        (*list).n_expr = index.wrapping_add(1);
        let item = (*list).items.wrapping_add(index as u32 as usize);
        core::ptr::write(
            item,
            ExprListItem {
                p_expr: core::ptr::null_mut(),
                p_name: core::ptr::null_mut(),
                sort_agg_state: 0,
            },
        );
        (*item).p_name = name_from_token(db, name);
        (*item).p_expr = expr;
    }

    list
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::tracked::BLOCK_HEADER_SIZE;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::sqlite::mem::{DbMemOps, DB_MEM_OPS, DEFAULT_DB_MEM_OPS};
    use crate::sqlite::mem::tests::{Connection, OPS_LOCK};
    use std::sync::MutexGuard;

    static mut RESULTS: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut RESULT_INDEX: usize = 0;
    static mut REQUESTS: [(usize, i32); 3] = [(0, 0); 3];
    static mut REQUEST_COUNT: usize = 0;

    unsafe extern "C" fn split_alloc(p: *mut u8, n: i32) -> *mut u8 {
        let index = core::ptr::read(core::ptr::addr_of!(RESULT_INDEX));
        (*core::ptr::addr_of_mut!(REQUESTS))[index] = (p as usize, n);
        core::ptr::write(core::ptr::addr_of_mut!(REQUEST_COUNT), index + 1);
        core::ptr::write(core::ptr::addr_of_mut!(RESULT_INDEX), index + 1);
        (*core::ptr::addr_of!(RESULTS))[index]
    }

    unsafe extern "C" fn split_malloc(n: i32) -> *mut u8 {
        split_alloc(core::ptr::null_mut(), n)
    }

    unsafe extern "C" fn split_realloc(p: *mut u8, n: i32) -> *mut u8 {
        split_alloc(p, n)
    }

    fn install_split(first: *mut u8, second: *mut u8) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(RESULTS), [first, second, core::ptr::null_mut()]);
            core::ptr::write(core::ptr::addr_of_mut!(RESULT_INDEX), 0);
            core::ptr::write(core::ptr::addr_of_mut!(REQUEST_COUNT), 0);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(DB_MEM_OPS),
                DbMemOps { malloc: split_malloc, realloc: split_realloc },
            );
        }
        guard
    }

    unsafe fn set_third_result(result: *mut u8) {
        (*core::ptr::addr_of_mut!(RESULTS))[2] = result;
    }

    unsafe fn requests() -> [(usize, i32); 3] {
        core::ptr::read(core::ptr::addr_of!(REQUESTS))
    }

    unsafe fn request_count() -> usize {
        core::ptr::read(core::ptr::addr_of!(REQUEST_COUNT))
    }

    unsafe fn restore_default_ops() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
    }

    #[repr(align(32))]
    struct TrackedBlock([u8; 128]);

    impl TrackedBlock {
        fn new(size: i32) -> Self {
            let mut block = TrackedBlock([0; 128]);
            block.0[0..4].copy_from_slice(&size.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }

        fn payload(&mut self) -> *mut u8 {
            unsafe { self.0.as_mut_ptr().add(32) }
        }
    }

    #[repr(align(8))]
    struct Token {
        storage: [u8; 2 * core::mem::size_of::<*const u8>()],
    }

    impl Token {
        fn new(z: *const u8, n: u32) -> Self {
            let mut token = Token { storage: [0; 2 * core::mem::size_of::<*const u8>()] };
            unsafe {
                (token.storage.as_mut_ptr() as *mut *const u8).write(z);
                (token.storage.as_mut_ptr().add(core::mem::size_of::<*const u8>()) as *mut u32)
                    .write(n << 1);
            }
            token
        }

        fn ptr(&self) -> *const u8 {
            self.storage.as_ptr()
        }
    }

    #[repr(C)]
    struct Parse {
        db: *mut u8,
    }

    fn parse_for(db: &mut Connection) -> Parse {
        Parse { db: db.ptr() }
    }

    #[test]
    fn new_list_grows_to_four_and_appends_a_dequoted_name() {
        let mut db = Connection::healthy();
        let mut parse = parse_for(&mut db);
        let mut header = ExprList {
            n_expr: 0,
            n_alloc: 0,
            _gap_08: [0; 0x0c - 0x08],
            items: core::ptr::null_mut(),
        };
        let mut items: [ExprListItem; 4] = core::array::from_fn(|_| ExprListItem {
            p_expr: 0xfeedusize as *mut u8,
            p_name: 0xbeefusize as *mut u8,
            sort_agg_state: u32::MAX,
        });
        let text = b"\"a\"";
        let token = Token::new(text.as_ptr(), 3);
        let mut name = [0xa5u8; 4];
        let _guard = install_split((&mut header as *mut ExprList).cast(), items.as_mut_ptr().cast());
        unsafe { set_third_result(name.as_mut_ptr()) };
        let expr = 0x1234usize as *mut u8;

        let result = unsafe {
            expr_list_append((&mut parse as *mut Parse).cast(), core::ptr::null_mut(), expr, token.ptr())
        };

        assert!(core::ptr::eq(result, &mut header));
        assert_eq!(unsafe { request_count() }, 3);
        assert_eq!(unsafe { requests() }, [(0, 0x10), (0, 0x30), (0, 4)]);
        assert_eq!(header.n_expr, 1);
        assert_eq!(header.n_alloc, 4);
        assert_eq!(header.items, items.as_mut_ptr());
        assert_eq!(items[0].p_expr, expr);
        assert_eq!(items[0].p_name, name.as_mut_ptr());
        assert_eq!(&name[..2], b"a\0", "name_from_token duplicates and dequotes the token");
        assert_eq!(items[0].sort_agg_state, 0, "stmia clears all three target words");
        unsafe { restore_default_ops() };
    }

    #[test]
    fn full_list_doubles_capacity_and_uses_the_old_count_as_index() {
        let mut db = Connection::healthy();
        let mut parse = parse_for(&mut db);
        let mut old_items = [ExprListItem {
            p_expr: 0x1111usize as *mut u8,
            p_name: 0x2222usize as *mut u8,
            sort_agg_state: 0x3333_4444,
        }];
        let mut new_items: [ExprListItem; 6] = core::array::from_fn(|_| ExprListItem {
            p_expr: old_items[0].p_expr,
            p_name: old_items[0].p_name,
            sort_agg_state: old_items[0].sort_agg_state,
        });
        let mut list = ExprList {
            n_expr: 1,
            n_alloc: 1,
            _gap_08: [0xa5; 0x0c - 0x08],
            items: old_items.as_mut_ptr(),
        };
        let _guard = install_split(new_items.as_mut_ptr().cast(), core::ptr::null_mut());
        let expr = 0x5555usize as *mut u8;

        let result = unsafe {
            expr_list_append((&mut parse as *mut Parse).cast(), &mut list, expr, core::ptr::null())
        };

        assert!(core::ptr::eq(result, &mut list));
        assert_eq!(unsafe { request_count() }, 1);
        assert_eq!(unsafe { requests()[0] }, (old_items.as_mut_ptr() as usize, 0x48));
        assert_eq!(list.n_expr, 2);
        assert_eq!(list.n_alloc, 6);
        assert_eq!(new_items[0].p_expr, old_items[0].p_expr, "realloc preserves old entries");
        assert_eq!(new_items[1].p_expr, expr);
        assert!(new_items[1].p_name.is_null());
        assert_eq!(new_items[1].sort_agg_state, 0);
        unsafe { restore_default_ops() };
    }

    #[test]
    fn two_null_inputs_leave_a_spare_capacity_list_unchanged() {
        let mut db = Connection::healthy();
        let mut parse = parse_for(&mut db);
        let mut list = ExprList {
            n_expr: 0,
            n_alloc: 1,
            _gap_08: [0xa5; 0x0c - 0x08],
            items: core::ptr::null_mut(),
        };
        let _guard = install_split(core::ptr::null_mut(), core::ptr::null_mut());

        let result = unsafe {
            expr_list_append(
                (&mut parse as *mut Parse).cast(),
                &mut list,
                core::ptr::null_mut(),
                core::ptr::null(),
            )
        };

        assert!(core::ptr::eq(result, &mut list));
        assert_eq!(list.n_expr, 0);
        assert_eq!(list.n_alloc, 1);
        assert_eq!(unsafe { request_count() }, 0, "both inputs zero skip every call");
        unsafe { restore_default_ops() };
    }

    #[test]
    fn failed_new_list_allocation_returns_null_and_latches_the_connection() {
        let mut db = Connection::healthy();
        let mut parse = parse_for(&mut db);
        let _guard = install_split(core::ptr::null_mut(), core::ptr::null_mut());

        let result = unsafe {
            expr_list_append(
                (&mut parse as *mut Parse).cast(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null(),
            )
        };

        assert!(result.is_null());
        assert_eq!(unsafe { request_count() }, 1);
        assert_eq!(unsafe { requests()[0] }, (0, 0x10));
        assert_eq!(db.failed_flag(), 1);
        unsafe { restore_default_ops() };
    }

    #[test]
    fn failed_resize_deletes_the_existing_list_and_sets_malloc_failed() {
        let _heap = mock_heap();
        let mut db = Connection::healthy();
        let mut parse = parse_for(&mut db);
        let mut header = TrackedBlock::new(0x10);
        let mut item_array = TrackedBlock::new(0x0c);
        let list = header.payload() as *mut ExprList;
        unsafe {
            core::ptr::write(
                list,
                ExprList {
                    n_expr: 0,
                    n_alloc: 0,
                    _gap_08: [0; 0x0c - 0x08],
                    items: item_array.payload().cast(),
                },
            );
        }
        let _guard = install_split(core::ptr::null_mut(), core::ptr::null_mut());

        let result = unsafe {
            expr_list_append(
                (&mut parse as *mut Parse).cast(),
                list,
                core::ptr::null_mut(),
                core::ptr::null(),
            )
        };

        assert!(result.is_null());
        assert_eq!(unsafe { requests()[0] }, (item_array.payload() as usize, 0x30));
        assert_eq!(db.failed_flag(), 1);
        assert_eq!(free_log().0, 2, "items then header are released through sqlite3_free");
        unsafe { restore_default_ops() };
    }
}
