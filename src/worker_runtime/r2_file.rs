use axum::extract::multipart::Field;
use worker::{Bucket, MultipartUpload, UploadedPart};

use crate::error::AppError;

pub const FILE_UPLOAD_LIMIT_BYTES: u64 = 95 * 1024 * 1024;
pub const REQUEST_BODY_LIMIT_BYTES: usize = 100_000_000;
pub const FIXED_LENGTH_HEADER: &str = "x-warden-fixed-length";
const R2_PART_SIZE_BYTES: usize = 8 * 1024 * 1024;

async fn abort_upload(upload: &MultipartUpload) {
    if let Err(err) = upload.abort().await {
        log::warn!("failed to abort R2 multipart upload: {err}");
    }
}

async fn upload_part(
    upload: &MultipartUpload,
    parts: &mut Vec<UploadedPart>,
    part_number: &mut u16,
    bytes: Vec<u8>,
) -> Result<(), AppError> {
    let part = upload
        .upload_part(*part_number, bytes)
        .await
        .map_err(|_| AppError::Internal)?;
    parts.push(part);
    *part_number = part_number.checked_add(1).ok_or(AppError::Internal)?;
    Ok(())
}

pub async fn upload_field(
    bucket: &Bucket,
    object_key: &str,
    field: &mut Field<'_>,
) -> Result<u64, AppError> {
    let mut total = 0_u64;
    let mut buffer = Vec::with_capacity(R2_PART_SIZE_BYTES);
    let mut multipart: Option<MultipartUpload> = None;
    let mut parts = Vec::new();
    let mut part_number = 1_u16;

    loop {
        let chunk = match field.chunk().await {
            Ok(chunk) => chunk,
            Err(err) => {
                if let Some(upload) = multipart.as_ref() {
                    abort_upload(upload).await;
                }
                return Err(AppError::BadRequest(format!(
                    "Invalid multipart data: {err}"
                )));
            }
        };
        let Some(chunk) = chunk else { break };

        total = total
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| AppError::PayloadTooLarge("File exceeds 95 MiB".to_string()))?;
        if total > FILE_UPLOAD_LIMIT_BYTES {
            if let Some(upload) = multipart.as_ref() {
                abort_upload(upload).await;
            }
            return Err(AppError::PayloadTooLarge(
                "File exceeds the 95 MiB upload limit".to_string(),
            ));
        }

        let mut remaining = chunk.as_ref();
        while !remaining.is_empty() {
            let take = (R2_PART_SIZE_BYTES - buffer.len()).min(remaining.len());
            buffer.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];

            if buffer.len() == R2_PART_SIZE_BYTES {
                if multipart.is_none() {
                    multipart = Some(
                        bucket
                            .create_multipart_upload(object_key)
                            .execute()
                            .await
                            .map_err(|_| AppError::Internal)?,
                    );
                }
                let bytes = std::mem::replace(&mut buffer, Vec::with_capacity(R2_PART_SIZE_BYTES));
                let upload = multipart.as_ref().ok_or(AppError::Internal)?;
                if let Err(err) = upload_part(upload, &mut parts, &mut part_number, bytes).await {
                    abort_upload(upload).await;
                    return Err(err);
                }
            }
        }
    }

    let Some(upload) = multipart else {
        bucket
            .put(object_key, buffer)
            .execute()
            .await
            .map_err(|_| AppError::Internal)?;
        return Ok(total);
    };

    if !buffer.is_empty()
        && let Err(err) = upload_part(&upload, &mut parts, &mut part_number, buffer).await
    {
        abort_upload(&upload).await;
        return Err(err);
    }

    let upload_id = upload.upload_id().await;
    if upload.complete(parts).await.is_err() {
        if let Ok(upload) = bucket.resume_multipart_upload(object_key, upload_id) {
            abort_upload(&upload).await;
        }
        return Err(AppError::Internal);
    }
    Ok(total)
}

pub fn validate_declared_size(size: i64, kind: &str) -> Result<(), AppError> {
    if size < 0 {
        return Err(AppError::BadRequest(format!(
            "{kind} size can't be negative"
        )));
    }
    if size as u64 > FILE_UPLOAD_LIMIT_BYTES {
        return Err(AppError::PayloadTooLarge(format!(
            "{kind} exceeds the 95 MiB upload limit"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FILE_UPLOAD_LIMIT_BYTES, REQUEST_BODY_LIMIT_BYTES, validate_declared_size};

    #[test]
    fn upload_limits_match_cloudflare_free_safety_margin() {
        assert_eq!(FILE_UPLOAD_LIMIT_BYTES, 99_614_720);
        assert_eq!(REQUEST_BODY_LIMIT_BYTES, 100_000_000);
        assert!(validate_declared_size(FILE_UPLOAD_LIMIT_BYTES as i64, "File").is_ok());
        assert!(validate_declared_size(FILE_UPLOAD_LIMIT_BYTES as i64 + 1, "File").is_err());
    }
}
