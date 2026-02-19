use crate::error::AppError;
use worker::{D1Database, Env};

pub fn get_db(env: &Env) -> Result<D1Database, AppError> {
    env.d1("vaultsql").map_err(AppError::Worker)
}
