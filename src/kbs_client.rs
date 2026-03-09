// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 Red Hat, Inc.

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use std::fs;

/// Sends the DEK to the KBS via POST to be wrapped.
/// Saves the resulting KEK (response body) to the output file.
pub fn wrap_key(input_key_path: &str, kbs_url: &str, output_path: &str) -> Result<()> {
    let key_data = fs::read(input_key_path)
        .with_context(|| format!("Failed to read DEK file: {}", input_key_path))?;

    let client = Client::new();
    let url = format!("{}/kbs/v0/pkcs11/wrap-key", kbs_url.trim_end_matches('/'));

    println!("POSTing DEK to {} ...", url);

    let response = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .body(key_data)
        .send()
        .context("Failed to send POST request to KBS")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        anyhow::bail!("KBS returned error {}: {}", status, body);
    }

    let wrapped_key = response.bytes().context("Failed to read response body")?;

    fs::write(output_path, &wrapped_key)
        .with_context(|| format!("Failed to save wrapped key to {}", output_path))?;

    println!("Success: Wrapped key (KEK) saved to {}", output_path);
    Ok(())
}

/// Retrieves the original DEK from the KBS via GET by providing the wrapped KEK.
/// Saves the resulting DEK (response body) to the output file.
pub fn unwrap_key(input_kek_path: &str, kbs_url: &str, output_path: &str) -> Result<()> {
    let kek_data = fs::read(input_kek_path)
        .with_context(|| format!("Failed to read KEK file: {}", input_kek_path))?;

    let client = Client::new();
    let url = format!("{}/kbs/v0/pkcs11/wrap-key", kbs_url.trim_end_matches('/'));

    println!("GETting DEK from {} using KEK ...", url);

    let response = client
        .get(&url)
        .header("Content-Type", "application/octet-stream")
        .body(kek_data)
        .send()
        .context("Failed to send GET request to KBS")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        anyhow::bail!("KBS returned error {}: {}", status, body);
    }

    let unwrapped_key = response.bytes().context("Failed to read response body")?;

    fs::write(output_path, &unwrapped_key)
        .with_context(|| format!("Failed to save unwrapped key to {}", output_path))?;

    println!("Success: Unwrapped key (DEK) saved to {}", output_path);
    Ok(())
}
