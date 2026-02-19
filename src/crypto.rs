use base64::{engine::general_purpose, Engine as _};
use constant_time_eq::constant_time_eq;
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::CryptoKey;

pub const ITERATIONS: u32 = 100_000;

async fn get_subtle_crypto() -> Result<web_sys::SubtleCrypto, String> {
    let global = js_sys::global();
    let crypto_val = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|e| format!("Failed to get crypto: {:?}", e))?;
    let crypto = crypto_val
        .dyn_into::<web_sys::Crypto>()
        .map_err(|_| "Failed to cast to Crypto".to_string())?;
    
    // crypto.subtle() returns SubtleCrypto directly in recent web-sys, or Result in older?
    // Based on error "no method named map_err", it returns SubtleCrypto.
    Ok(crypto.subtle())
}

pub async fn hash_password(password: &str, salt: &str) -> Result<String, String> {
    let salt_bytes = general_purpose::STANDARD
        .decode(salt)
        .map_err(|e| format!("Invalid salt: {}", e))?;

    let subtle = get_subtle_crypto().await?;

    // Encode password to bytes
    let enc = web_sys::TextEncoder::new().map_err(|_| "Failed to create TextEncoder".to_string())?;
    // encode_with_input returns Vec<u8> in some web-sys versions, or Uint8Array.
    // The compiler said Vec<u8>, so let's convert it.
    let password_vec = enc.encode_with_input(password);
    let password_bytes = Uint8Array::from(&password_vec[..]);

    // Import password as key
    // Algorithm: "PBKDF2"
    let key_usages = Array::of1(&JsValue::from_str("deriveBits"));

    let key_promise = subtle
        .import_key_with_str(
            "raw",
            &password_bytes, // Uint8Array implements Object
            "PBKDF2",
            false,
            &key_usages,
        )
        .map_err(|e| format!("ImportKey failed: {:?}", e))?;

    let key_val = JsFuture::from(key_promise)
        .await
        .map_err(|e| format!("ImportKey promise failed: {:?}", e))?;
    let key = key_val
        .dyn_into::<CryptoKey>()
        .map_err(|_| "ImportKey result is not a CryptoKey".to_string())?;

    // Derive bits
    // Params: { name: "PBKDF2", salt: ..., iterations: ..., hash: "SHA-256" }
    let params = Object::new();
    Reflect::set(&params, &"name".into(), &"PBKDF2".into())
        .map_err(|e| format!("Failed to set params name: {:?}", e))?;
    Reflect::set(&params, &"salt".into(), &Uint8Array::from(&salt_bytes[..]))
        .map_err(|e| format!("Failed to set params salt: {:?}", e))?;
    Reflect::set(&params, &"iterations".into(), &JsValue::from(ITERATIONS))
        .map_err(|e| format!("Failed to set params iterations: {:?}", e))?;
    Reflect::set(&params, &"hash".into(), &"SHA-256".into())
        .map_err(|e| format!("Failed to set params hash: {:?}", e))?;

    let derive_promise = subtle
        .derive_bits_with_object(
            &params,
            &key,
            256, // 256 bits
        )
        .map_err(|e| format!("DeriveBits failed: {:?}", e))?;

    let derived_bits_val = JsFuture::from(derive_promise)
        .await
        .map_err(|e| format!("DeriveBits promise failed: {:?}", e))?;
    
    let derived_array = Uint8Array::new(&derived_bits_val);
    let mut derived_vec = vec![0u8; derived_array.length() as usize];
    derived_array.copy_to(&mut derived_vec);

    Ok(general_purpose::STANDARD.encode(&derived_vec))
}

pub fn generate_salt() -> String {
    let mut salt = [0u8; 32];
    let global = js_sys::global();
    
    if let Ok(crypto_val) = js_sys::Reflect::get(&global, &JsValue::from_str("crypto")) {
        if let Ok(crypto) = crypto_val.dyn_into::<web_sys::Crypto>() {
             let array = Uint8Array::new_with_length(32);
             if crypto.get_random_values_with_array_buffer_view(&array).is_ok() {
                 let mut vec = vec![0u8; 32];
                 array.copy_to(&mut vec);
                 return general_purpose::STANDARD.encode(&vec);
             }
        }
    }

    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    general_purpose::STANDARD.encode(salt)
}

pub async fn verify_password(password: &str, salt: &str, hash: &str) -> bool {
    match hash_password(password, salt).await {
        Ok(new_hash) => constant_time_eq(new_hash.as_bytes(), hash.as_bytes()),
        Err(_) => false,
    }
}
