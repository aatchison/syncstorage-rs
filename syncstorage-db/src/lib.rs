//! Generic db abstration.

#[cfg(test)]
#[macro_use]
extern crate slog_scope;

pub mod mock;
#[cfg(test)]
mod tests;

#[cfg(feature = "mysql")]
pub type DbPoolImpl = syncstorage_mysql::MysqlDbPool;
#[cfg(feature = "mysql")]
pub use syncstorage_mysql::DbError;
#[cfg(feature = "mysql")]
pub type DbImpl = syncstorage_mysql::MysqlDb;

pub use syncserver_db_common::{GetPoolState, PoolState};
pub use syncstorage_db_common::error::DbErrorIntrospect;

pub use syncstorage_db_common::{
    params, results,
    util::{to_rfc3339, SyncTimestamp},
    Db, DbPool, Sorting, UserIdentifier,
};

