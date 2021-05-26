use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Executor, FromRow};
use std::fmt::{Display, Formatter};
use anyhow::{Result, Context};
struct DB {
  pool: PgPool
}

#[derive(FromRow, Debug)]
pub struct User {
  pub id: Option<i64>,
  pub name: String,
  pub email: String
}

impl Display for User {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self.id {
      Some(i) => write!(f, "id: {}, name: {}, email: {}", i, self.name, self.email),
      None => write!(f, "id: None, name: {}, email: {}", self.name, self.email),
    }
  }
}

impl User {
  //  pub async fn fetch_one<'e, 'c: 'e, E>(self, executor: E) -> Result<O, Error>
  // E: 'e + Executor<'c, Database = DB>,
  pub async fn insert<'e, 'c: 'e, E>(&mut self, ex: E) -> Result<()> 
  where E: 'e + sqlx::Executor<'c, Database = sqlx::Postgres>
  {
    let id = sqlx::query_scalar::<_, i64>("insert into users(name, email) values($1, $2) returning id")
    .bind(self.name.clone()).bind(self.email.clone())
    .fetch_one(ex).await.context("Unable to save")?;
    self.id = Some(id);
    Ok(())
  }
}

impl DB {
  pub async fn new() -> Result<Self> {
    let pool =PgPoolOptions::new()
      .max_connections(5)
      .connect("postgres:///testdb?sslmode=disable")
      .await.context("Unable to connect")?;
    Ok(DB{pool})
  }

  pub async fn migrate(&self) -> Result<()> {
    sqlx::migrate!().run(&self.pool).await.context("Failed to run migrations")
  }
}

#[cfg(test)]
mod tests {
  use sqlx::Acquire;
use tokio::runtime::Runtime;
  use super::{DB, User};
  #[test]
  fn test_should_connect() {
    let rt = Runtime::new().unwrap();
    let db = rt.block_on(DB::new()).unwrap();
    rt.block_on(db.migrate()).unwrap();
    let mut u = User{
      id: None, 
      name: "Vagmi".into(), 
      email: "vagmi@example.com".into()
    };
    let mut t = rt.block_on(db.pool.begin()).unwrap();

    let mut t1 = rt.block_on(t.begin()).unwrap();
    rt.block_on(u.insert(&mut t1)).unwrap();
    rt.block_on(t1.commit()).unwrap();
    match u.id {
      Some(id) => println!("{}", u),
      None => panic!()
    }
    rt.block_on(t.rollback()).unwrap();
  }
}