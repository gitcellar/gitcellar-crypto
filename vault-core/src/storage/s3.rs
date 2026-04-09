//! S3-compatible cloud storage backend
//!
//! Supports any S3-compatible storage provider:
//! - **Backblaze B2** (via S3-compatible API)
//! - **Wasabi**
//! - **MinIO**
//! - **AWS S3**
//! - Any other S3-compatible service

use super::StorageBackend;
use crate::error::{VaultError, VaultResult};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

/// S3 storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    /// S3 endpoint URL (e.g., "https://s3.us-west-000.backblazeb2.com")
    pub endpoint: String,

    /// Bucket name
    pub bucket: String,

    /// Access key ID (or Application Key ID for B2)
    pub access_key_id: String,

    /// Secret access key (or Application Key for B2)
    pub secret_access_key: String,

    /// AWS region (e.g., "us-west-000" for B2, "us-east-1" for AWS)
    pub region: String,

    /// Optional path prefix within the bucket
    pub prefix: Option<String>,
}

impl S3Config {
    /// Create configuration for Backblaze B2
    ///
    /// # Arguments
    /// * `key_id` - B2 Application Key ID
    /// * `app_key` - B2 Application Key
    /// * `bucket` - Bucket name
    /// * `region` - B2 region (e.g., "us-west-000")
    pub fn b2(key_id: &str, app_key: &str, bucket: &str, region: &str) -> Self {
        Self {
            endpoint: format!("https://s3.{}.backblazeb2.com", region),
            bucket: bucket.to_string(),
            access_key_id: key_id.to_string(),
            secret_access_key: app_key.to_string(),
            region: region.to_string(),
            prefix: None,
        }
    }

    /// Create configuration for Wasabi
    ///
    /// # Arguments
    /// * `access_key` - Wasabi access key
    /// * `secret_key` - Wasabi secret key
    /// * `bucket` - Bucket name
    /// * `region` - Wasabi region (e.g., "us-east-1")
    pub fn wasabi(access_key: &str, secret_key: &str, bucket: &str, region: &str) -> Self {
        Self {
            endpoint: format!("https://s3.{}.wasabisys.com", region),
            bucket: bucket.to_string(),
            access_key_id: access_key.to_string(),
            secret_access_key: secret_key.to_string(),
            region: region.to_string(),
            prefix: None,
        }
    }

    /// Create configuration for AWS S3
    ///
    /// # Arguments
    /// * `access_key` - AWS access key ID
    /// * `secret_key` - AWS secret access key
    /// * `bucket` - Bucket name
    /// * `region` - AWS region (e.g., "us-east-1")
    pub fn aws(access_key: &str, secret_key: &str, bucket: &str, region: &str) -> Self {
        Self {
            endpoint: format!("https://s3.{}.amazonaws.com", region),
            bucket: bucket.to_string(),
            access_key_id: access_key.to_string(),
            secret_access_key: secret_key.to_string(),
            region: region.to_string(),
            prefix: None,
        }
    }

    /// Create configuration for MinIO
    ///
    /// # Arguments
    /// * `endpoint` - MinIO server URL (e.g., "http://localhost:9000")
    /// * `access_key` - MinIO access key
    /// * `secret_key` - MinIO secret key
    /// * `bucket` - Bucket name
    pub fn minio(endpoint: &str, access_key: &str, secret_key: &str, bucket: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            bucket: bucket.to_string(),
            access_key_id: access_key.to_string(),
            secret_access_key: secret_key.to_string(),
            region: "us-east-1".to_string(), // MinIO default
            prefix: None,
        }
    }

    /// Set a path prefix for all objects
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = Some(prefix.trim_matches('/').to_string());
        self
    }
}

/// S3-compatible storage backend
pub struct S3Storage {
    config: S3Config,
    client: Client,
}

impl S3Storage {
    /// Create a new S3 storage backend
    pub fn new(config: S3Config) -> VaultResult<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| VaultError::Network(format!("Failed to create HTTP client: {}", e)))?;

        info!(
            "Initialized S3 storage: {} bucket={}",
            config.endpoint, config.bucket
        );

        Ok(Self { config, client })
    }

    /// Get the full object key (with prefix if configured)
    fn object_key(&self, path: &str) -> String {
        match &self.config.prefix {
            Some(prefix) => format!("{}/{}", prefix, path),
            None => path.to_string(),
        }
    }

    /// Build the object URL
    fn object_url(&self, key: &str) -> String {
        format!("{}/{}/{}", self.config.endpoint, self.config.bucket, key)
    }

    /// Sign a request using AWS Signature Version 4
    fn sign_request(
        &self,
        method: &str,
        url: &str,
        _headers: &[(String, String)],
        payload_hash: &str,
    ) -> VaultResult<Vec<(String, String)>> {
        use chrono::Utc;
        use hmac::{Hmac, Mac};

        type HmacSha256 = Hmac<Sha256>;

        let now = Utc::now();
        let date_stamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        // Parse URL
        let parsed_url = url::Url::parse(url)
            .map_err(|e| VaultError::Network(format!("Invalid URL: {}", e)))?;

        let host = parsed_url
            .host_str()
            .ok_or_else(|| VaultError::Network("URL has no host".to_string()))?;

        let canonical_uri = parsed_url.path();
        let canonical_querystring = parsed_url.query().unwrap_or("");

        // Build canonical headers
        let mut canonical_headers = vec![
            format!("host:{}", host),
            format!("x-amz-content-sha256:{}", payload_hash),
            format!("x-amz-date:{}", amz_date),
        ];
        canonical_headers.sort();
        let canonical_headers_str = canonical_headers.join("\n") + "\n";

        let signed_headers = "host;x-amz-content-sha256;x-amz-date";

        // Create canonical request
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers_str,
            signed_headers,
            payload_hash
        );

        // Hash canonical request
        let mut hasher = Sha256::new();
        hasher.update(canonical_request.as_bytes());
        let canonical_request_hash = format!("{:x}", hasher.finalize());

        // Create string to sign
        let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, self.config.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date, credential_scope, canonical_request_hash
        );

        // Calculate signing key
        let k_secret = format!("AWS4{}", self.config.secret_access_key);

        let mut mac = HmacSha256::new_from_slice(k_secret.as_bytes())
            .map_err(|e| VaultError::Internal(format!("HMAC error: {}", e)))?;
        mac.update(date_stamp.as_bytes());
        let k_date = mac.finalize().into_bytes();

        let mut mac = HmacSha256::new_from_slice(&k_date)
            .map_err(|e| VaultError::Internal(format!("HMAC error: {}", e)))?;
        mac.update(self.config.region.as_bytes());
        let k_region = mac.finalize().into_bytes();

        let mut mac = HmacSha256::new_from_slice(&k_region)
            .map_err(|e| VaultError::Internal(format!("HMAC error: {}", e)))?;
        mac.update(b"s3");
        let k_service = mac.finalize().into_bytes();

        let mut mac = HmacSha256::new_from_slice(&k_service)
            .map_err(|e| VaultError::Internal(format!("HMAC error: {}", e)))?;
        mac.update(b"aws4_request");
        let k_signing = mac.finalize().into_bytes();

        // Sign the string
        let mut mac = HmacSha256::new_from_slice(&k_signing)
            .map_err(|e| VaultError::Internal(format!("HMAC error: {}", e)))?;
        mac.update(string_to_sign.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        // Build authorization header
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.config.access_key_id, credential_scope, signed_headers, signature
        );

        Ok(vec![
            ("Authorization".to_string(), authorization),
            ("x-amz-date".to_string(), amz_date),
            ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
            ("Host".to_string(), host.to_string()),
        ])
    }

    /// Compute SHA256 hash of payload
    fn payload_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

#[async_trait::async_trait]
impl StorageBackend for S3Storage {
    async fn upload(&self, path: &str, data: &[u8]) -> VaultResult<()> {
        let key = self.object_key(path);
        let url = self.object_url(&key);
        let payload_hash = Self::payload_hash(data);

        let auth_headers = self.sign_request("PUT", &url, &[], &payload_hash)?;

        let mut request = self.client.put(&url).body(data.to_vec());

        for (name, value) in auth_headers {
            request = request.header(&name, &value);
        }

        let response = request.send().await.map_err(|e| {
            VaultError::Network(format!("Upload request failed: {}", e))
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Storage(format!(
                "Upload failed with status {}: {}",
                status, body
            )));
        }

        debug!("Uploaded {} bytes to s3://{}/{}", data.len(), self.config.bucket, key);

        Ok(())
    }

    async fn download(&self, path: &str) -> VaultResult<Vec<u8>> {
        let key = self.object_key(path);
        let url = self.object_url(&key);
        let payload_hash = Self::payload_hash(&[]); // Empty payload for GET

        let auth_headers = self.sign_request("GET", &url, &[], &payload_hash)?;

        let mut request = self.client.get(&url);

        for (name, value) in auth_headers {
            request = request.header(&name, &value);
        }

        let response = request.send().await.map_err(|e| {
            VaultError::Network(format!("Download request failed: {}", e))
        })?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(VaultError::Storage(format!(
                "Object not found: s3://{}/{}",
                self.config.bucket, key
            )));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Storage(format!(
                "Download failed with status {}: {}",
                status, body
            )));
        }

        let data = response.bytes().await.map_err(|e| {
            VaultError::Network(format!("Failed to read response body: {}", e))
        })?;

        debug!(
            "Downloaded {} bytes from s3://{}/{}",
            data.len(),
            self.config.bucket,
            key
        );

        Ok(data.to_vec())
    }

    async fn exists(&self, path: &str) -> VaultResult<bool> {
        let key = self.object_key(path);
        let url = self.object_url(&key);
        let payload_hash = Self::payload_hash(&[]);

        let auth_headers = self.sign_request("HEAD", &url, &[], &payload_hash)?;

        let mut request = self.client.head(&url);

        for (name, value) in auth_headers {
            request = request.header(&name, &value);
        }

        let response = request.send().await.map_err(|e| {
            VaultError::Network(format!("HEAD request failed: {}", e))
        })?;

        Ok(response.status().is_success())
    }

    async fn list(&self, prefix: &str) -> VaultResult<Vec<String>> {
        let full_prefix = self.object_key(prefix);
        let url = format!(
            "{}/{}?list-type=2&prefix={}",
            self.config.endpoint,
            self.config.bucket,
            urlencoding::encode(&full_prefix)
        );
        let payload_hash = Self::payload_hash(&[]);

        let auth_headers = self.sign_request("GET", &url, &[], &payload_hash)?;

        let mut request = self.client.get(&url);

        for (name, value) in auth_headers {
            request = request.header(&name, &value);
        }

        let response = request.send().await.map_err(|e| {
            VaultError::Network(format!("List request failed: {}", e))
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Storage(format!(
                "List failed with status {}: {}",
                status, body
            )));
        }

        let body = response.text().await.map_err(|e| {
            VaultError::Network(format!("Failed to read list response: {}", e))
        })?;

        // Parse XML response (simplified - just extract Key elements)
        let mut keys = Vec::new();
        for cap in regex_lite::Regex::new(r"<Key>([^<]+)</Key>")
            .unwrap()
            .captures_iter(&body)
        {
            if let Some(key) = cap.get(1) {
                let key_str = key.as_str();
                // Remove prefix to get relative path
                let relative = match &self.config.prefix {
                    Some(p) => key_str.strip_prefix(&format!("{}/", p)).unwrap_or(key_str),
                    None => key_str,
                };
                keys.push(relative.to_string());
            }
        }

        Ok(keys)
    }

    async fn delete(&self, path: &str) -> VaultResult<()> {
        let key = self.object_key(path);
        let url = self.object_url(&key);
        let payload_hash = Self::payload_hash(&[]);

        let auth_headers = self.sign_request("DELETE", &url, &[], &payload_hash)?;

        let mut request = self.client.delete(&url);

        for (name, value) in auth_headers {
            request = request.header(&name, &value);
        }

        let response = request.send().await.map_err(|e| {
            VaultError::Network(format!("Delete request failed: {}", e))
        })?;

        // S3 returns 204 for successful delete, but also doesn't error on non-existent
        if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Storage(format!(
                "Delete failed with status {}: {}",
                status, body
            )));
        }

        debug!("Deleted s3://{}/{}", self.config.bucket, key);

        Ok(())
    }

    fn backend_name(&self) -> &str {
        "s3"
    }
}

// Note: Integration tests for S3 require actual credentials
// Unit tests use mocking or are skipped
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_b2() {
        let config = S3Config::b2("key-id", "app-key", "my-bucket", "us-west-000");
        assert_eq!(config.endpoint, "https://s3.us-west-000.backblazeb2.com");
        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.region, "us-west-000");
    }

    #[test]
    fn test_config_wasabi() {
        let config = S3Config::wasabi("key", "secret", "bucket", "us-east-1");
        assert_eq!(config.endpoint, "https://s3.us-east-1.wasabisys.com");
    }

    #[test]
    fn test_config_aws() {
        let config = S3Config::aws("key", "secret", "bucket", "eu-west-1");
        assert_eq!(config.endpoint, "https://s3.eu-west-1.amazonaws.com");
    }

    #[test]
    fn test_config_minio() {
        let config = S3Config::minio("http://localhost:9000", "key", "secret", "bucket");
        assert_eq!(config.endpoint, "http://localhost:9000");
        assert_eq!(config.region, "us-east-1"); // MinIO default
    }

    #[test]
    fn test_config_with_prefix() {
        let config = S3Config::b2("key", "secret", "bucket", "region")
            .with_prefix("my-app/data");
        assert_eq!(config.prefix, Some("my-app/data".to_string()));
    }

    #[test]
    fn test_object_key_with_prefix() {
        let config = S3Config::b2("key", "secret", "bucket", "region")
            .with_prefix("prefix");
        let storage = S3Storage::new(config).unwrap();

        assert_eq!(storage.object_key("file.txt"), "prefix/file.txt");
    }

    #[test]
    fn test_object_key_without_prefix() {
        let config = S3Config::b2("key", "secret", "bucket", "region");
        let storage = S3Storage::new(config).unwrap();

        assert_eq!(storage.object_key("file.txt"), "file.txt");
    }

    #[test]
    fn test_payload_hash() {
        let hash = S3Storage::payload_hash(b"test data");
        assert_eq!(hash.len(), 64); // SHA256 hex is 64 chars
    }
}
