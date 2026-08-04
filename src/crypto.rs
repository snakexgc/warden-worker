pub mod password;

use base64::{Engine as _, engine::general_purpose};
use constant_time_eq::constant_time_eq;
#[cfg(target_arch = "wasm32")]
use js_sys::Uint8Array;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue};

// KDF 类型常量
pub const KDF_TYPE_PBKDF2: i32 = 0;
pub const KDF_TYPE_ARGON2ID: i32 = 1;

// 默认参数（与 vaultwarden 一致）
pub const PBKDF2_ITERATIONS_DEFAULT: i32 = 600_000;
pub const PBKDF2_ITERATIONS_MIN: i32 = 100_000;
pub const ARGON2ID_MEMORY_DEFAULT_MB: i32 = 64;
pub const ARGON2ID_PARALLELISM_DEFAULT: i32 = 4;
pub const PASSWORD_ITERATIONS_DEFAULT: i32 = 600_000;
const PASSWORD_SALT_LEN: usize = 64;

/// 使用 PBKDF2-HMAC-SHA256 哈希密码
///
/// # 参数
/// * `password` - 密码字符串
/// * `salt` - Base64 编码的盐值
/// * `iterations` - 迭代次数
///
/// # 返回
/// Base64 编码的哈希值
pub async fn hash_password_pbkdf2(
    password: &str,
    salt: &str,
    iterations: i32,
) -> Result<String, String> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let salt_bytes = general_purpose::STANDARD
        .decode(salt)
        .map_err(|e| format!("Invalid salt: {}", e))?;
    let iterations = u32::try_from(iterations)
        .map_err(|_| "PBKDF2 iterations must be greater than zero".to_string())?;
    if iterations == 0 {
        return Err("PBKDF2 iterations must be greater than zero".to_string());
    }

    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_bytes, iterations, &mut derived);
    Ok(general_purpose::STANDARD.encode(derived))
}

/// 验证 PBKDF2 密码
pub async fn verify_password_pbkdf2(
    password: &str,
    salt: &str,
    hash: &str,
    iterations: i32,
) -> bool {
    match hash_password_pbkdf2(password, salt, iterations).await {
        Ok(new_hash) => constant_time_eq(new_hash.as_bytes(), hash.as_bytes()),
        Err(_) => false,
    }
}

/// 验证 Argon2id 密码 (PHC 格式)
pub fn verify_password_argon2id(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, password_hash::PasswordVerifier};

    // 解析 PHC 格式哈希
    let parsed_hash = match argon2::password_hash::PasswordHash::new(hash) {
        Ok(h) => h,
        Err(e) => {
            log::warn!("Failed to parse Argon2 hash: {:?}", e);
            return false;
        }
    };

    // 验证密码
    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// 根据 KDF 类型验证密码
///
/// # 参数
/// * `password` - 密码字符串
/// * `salt` - Base64 编码的盐值 (PBKDF2 需要)
/// * `hash` - 存储的哈希值
/// * `kdf_type` - KDF 类型 (0=PBKDF2, 1=Argon2id)
/// * `iterations` - 迭代次数
/// * `memory` - 内存使用量 (Argon2id 专用)
/// * `parallelism` - 并行度 (Argon2id 专用)
///
/// # 返回
/// 密码是否匹配
pub async fn verify_password(
    password: &str,
    salt: &str,
    hash: &str,
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> bool {
    let kdf_name = match kdf_type {
        KDF_TYPE_PBKDF2 => "PBKDF2",
        KDF_TYPE_ARGON2ID => "Argon2id",
        _ => "Unknown",
    };
    log::info!(
        "[KDF] verify_password: type={} ({}), iterations={}, memory={:?}, parallelism={:?}",
        kdf_type,
        kdf_name,
        iterations,
        memory,
        parallelism
    );

    match kdf_type {
        KDF_TYPE_PBKDF2 => {
            log::debug!(
                "[KDF] Using PBKDF2 verification with {} iterations",
                iterations
            );
            verify_password_pbkdf2(password, salt, hash, iterations).await
        }
        KDF_TYPE_ARGON2ID => {
            log::debug!("[KDF] Using Argon2id verification (PHC format)");
            let _ = (salt, memory, parallelism);
            verify_password_argon2id(password, hash)
        }
        _ => {
            log::warn!("[KDF] Unknown KDF type: {}", kdf_type);
            false
        }
    }
}

fn generate_salt_bytes<const N: usize>() -> String {
    let mut salt = [0u8; N];
    #[cfg(target_arch = "wasm32")]
    {
        let global = js_sys::global();

        if let Ok(crypto_val) = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
            && let Ok(crypto) = crypto_val.dyn_into::<web_sys::Crypto>()
        {
            let array = Uint8Array::new_with_length(N as u32);
            if crypto
                .get_random_values_with_array_buffer_view(&array)
                .is_ok()
            {
                let mut vec = vec![0u8; N];
                array.copy_to(&mut vec);
                return general_purpose::STANDARD.encode(&vec);
            }
        }
    }

    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    general_purpose::STANDARD.encode(salt)
}

/// 生成与 Vaultwarden 一致的 64 字节服务端密码盐。
pub fn generate_password_salt() -> String {
    generate_salt_bytes::<PASSWORD_SALT_LEN>()
}

/// 使用 Vaultwarden 的服务端密码验证算法：PBKDF2-HMAC-SHA256，输出 32 字节。
pub async fn hash_server_password(
    password_hash: &str,
    salt: &str,
    iterations: i32,
) -> Result<String, String> {
    hash_password_pbkdf2(password_hash, salt, iterations).await
}

pub async fn verify_server_password(
    password_hash: &str,
    salt: &str,
    stored_hash: &str,
    iterations: i32,
) -> bool {
    match hash_server_password(password_hash, salt, iterations).await {
        Ok(candidate) => constant_time_eq(candidate.as_bytes(), stored_hash.as_bytes()),
        Err(error) => {
            log::warn!("Failed to calculate server password hash: {error}");
            false
        }
    }
}

/// 验证 KDF 参数
pub fn validate_kdf_params(
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> Result<(), String> {
    match kdf_type {
        KDF_TYPE_PBKDF2 => {
            if iterations < PBKDF2_ITERATIONS_MIN {
                return Err(format!(
                    "PBKDF2 iterations must be at least {}",
                    PBKDF2_ITERATIONS_MIN
                ));
            }
            Ok(())
        }
        KDF_TYPE_ARGON2ID => {
            if iterations < 1 {
                return Err("Argon2id iterations must be at least 1".to_string());
            }
            let memory =
                memory.ok_or_else(|| "Missing memory parameter for Argon2id".to_string())?;
            let parallelism = parallelism
                .ok_or_else(|| "Missing parallelism parameter for Argon2id".to_string())?;

            if !(15..=1024).contains(&memory) {
                return Err("Argon2id memory must be between 15 MB and 1024 MB".to_string());
            }
            if !(1..=16).contains(&parallelism) {
                return Err("Argon2id parallelism must be between 1 and 16".to_string());
            }
            Ok(())
        }
        _ => Err(format!("Invalid KDF type: {}", kdf_type)),
    }
}

/// 标准化 KDF 参数（用于响应）
pub fn normalize_kdf_params(
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> (Option<i32>, Option<i32>) {
    match kdf_type {
        KDF_TYPE_PBKDF2 => (None, None),
        KDF_TYPE_ARGON2ID => {
            if iterations < 1 {
                return (
                    Some(ARGON2ID_MEMORY_DEFAULT_MB),
                    Some(ARGON2ID_PARALLELISM_DEFAULT),
                );
            }
            let mem = memory.unwrap_or(ARGON2ID_MEMORY_DEFAULT_MB);
            let par = parallelism.unwrap_or(ARGON2ID_PARALLELISM_DEFAULT);
            let mem = if (15..=1024).contains(&mem) {
                mem
            } else {
                ARGON2ID_MEMORY_DEFAULT_MB
            };
            let par = if (1..=16).contains(&par) {
                par
            } else {
                ARGON2ID_PARALLELISM_DEFAULT
            };
            (Some(mem), Some(par))
        }
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_kdf_params_pbkdf2_valid() {
        assert!(validate_kdf_params(KDF_TYPE_PBKDF2, 600_000, None, None).is_ok());
    }

    #[test]
    fn test_validate_kdf_params_pbkdf2_invalid() {
        assert!(validate_kdf_params(KDF_TYPE_PBKDF2, 50_000, None, None).is_err());
    }

    #[test]
    fn test_validate_kdf_params_argon2id_valid() {
        assert!(validate_kdf_params(KDF_TYPE_ARGON2ID, 3, Some(64), Some(4)).is_ok());
    }

    #[test]
    fn test_validate_kdf_params_argon2id_invalid_memory() {
        assert!(validate_kdf_params(KDF_TYPE_ARGON2ID, 3, Some(10), Some(4)).is_err());
    }

    #[test]
    fn test_validate_kdf_params_argon2id_missing_params() {
        assert!(validate_kdf_params(KDF_TYPE_ARGON2ID, 3, None, Some(4)).is_err());
        assert!(validate_kdf_params(KDF_TYPE_ARGON2ID, 3, Some(64), None).is_err());
    }

    #[test]
    fn test_normalize_kdf_params_pbkdf2() {
        let (mem, par) = normalize_kdf_params(KDF_TYPE_PBKDF2, 600_000, None, None);
        assert_eq!(mem, None);
        assert_eq!(par, None);
    }

    #[test]
    fn test_normalize_kdf_params_argon2id_defaults() {
        let (mem, par) = normalize_kdf_params(KDF_TYPE_ARGON2ID, 0, None, None);
        assert_eq!(mem, Some(ARGON2ID_MEMORY_DEFAULT_MB));
        assert_eq!(par, Some(ARGON2ID_PARALLELISM_DEFAULT));
    }

    #[test]
    fn server_password_hash_matches_pbkdf2_sha256_vector() {
        let salt = general_purpose::STANDARD.encode(b"salt");
        let hash = futures::executor::block_on(hash_server_password("password", &salt, 1))
            .expect("PBKDF2 vector should hash");
        assert_eq!(hash, "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs=");
    }

    #[test]
    fn server_password_salt_is_64_bytes() {
        let salt = generate_password_salt();
        let decoded = general_purpose::STANDARD
            .decode(salt)
            .expect("password salt should be valid base64");
        assert_eq!(decoded.len(), 64);
    }
}
