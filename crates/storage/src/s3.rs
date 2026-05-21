//! S3 client for the sealed mnemonic ciphertext blob.

use crate::StorageError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use tracing::{debug, info};

pub struct S3Client {
    client: Client,
    bucket: String,
}

impl S3Client {
    pub fn new(client: Client, bucket: String) -> Self {
        Self { client, bucket }
    }

    /// Read the ciphertext blob. Returns `Err(StorageError::NotFound)`
    /// if the key doesn't exist (first-time bootstrap).
    pub async fn get_blob(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        debug!(bucket = %self.bucket, %key, "s3 get_object");
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(resp) => {
                let bytes = resp
                    .body
                    .collect()
                    .await
                    .map_err(|e| StorageError::Aws(format!("s3 body collect: {e}")))?
                    .into_bytes()
                    .to_vec();
                info!(bucket = %self.bucket, %key, "s3 got {} bytes", bytes.len());
                Ok(bytes)
            }
            Err(err) => {
                // `into_service_error()` collapses transport / dispatch /
                // timeout variants into a generic "unhandled" string that
                // tells us nothing. Match the SdkError directly so we
                // surface the real cause (often vsock-proxy connectivity
                // or TLS issues during the enclave's first boot).
                use aws_sdk_s3::error::SdkError;
                match err {
                    SdkError::ServiceError(svc) => {
                        let inner = svc.into_err();
                        if inner.is_no_such_key() {
                            Err(StorageError::NotFound(format!(
                                "s3://{}/{}",
                                self.bucket, key
                            )))
                        } else {
                            Err(StorageError::Aws(format!(
                                "s3 get_object service error: {inner:?}"
                            )))
                        }
                    }
                    other => Err(StorageError::Aws(format!(
                        "s3 get_object transport error: {other:?}"
                    ))),
                }
            }
        }
    }

    pub async fn put_blob(&self, key: &str, body: Vec<u8>) -> Result<(), StorageError> {
        debug!(bucket = %self.bucket, %key, len = body.len(), "s3 put_object");
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|e| StorageError::Aws(format!("s3 put_object: {e}")))?;
        info!(bucket = %self.bucket, %key, "s3 put ok");
        Ok(())
    }
}
