// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 Red Hat, Inc.

use anyhow::{Context, Result};
use openssl::symm::{Cipher, decrypt, encrypt};
use rand::RngCore;
use std::fs;

/// Encrypts a file using AES-256-CBC with a randomly generated key.
/// The IV (16 bytes) is prepended to the output file.
/// The key (32 bytes) is saved to a separate file.
pub fn encrypt_file(input_path: &str, output_path: &str, key_output_path: &str) -> Result<()> {
    // Read input data
    let data = fs::read(input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path))?;

    // Generate Key (32 bytes for AES-256)
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    // Generate IV (16 bytes for AES-256-CBC)
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Encrypt
    let cipher = Cipher::aes_256_cbc();
    let ciphertext = encrypt(cipher, &key, Some(&iv), &data)
        .context("AES-256-CBC encryption failed")?;

    // Construct Output: IV + Ciphertext
    let mut output_data = iv.to_vec();
    output_data.extend_from_slice(&ciphertext);

    // Write Encrypted File
    fs::write(output_path, output_data)
        .with_context(|| format!("Failed to write encrypted file: {}", output_path))?;

    // Write Key File
    fs::write(key_output_path, key)
        .with_context(|| format!("Failed to write key file: {}", key_output_path))?;

    println!("Encryption complete.");
    println!("  DEK saved to: {}", key_output_path);
    println!("  Encrypted data (IV + ciphertext) saved to: {}", output_path);

    Ok(())
}

pub fn decrypt_file(in_file: &str, in_key: &str, out_file: &str) -> Result<()> {
    // Read input data
    let data = fs::read(in_file)
        .with_context(|| format!("Failed to read input file: {}", in_file))?;

    let key = fs::read(in_key)
        .with_context(|| format!("Failed to read input key: {}", in_key))?;

    if data.len() < 16 {
     anyhow::bail!("File too short: {}", in_file);
    }

    let iv = &data[..16];
    let ciphertext = &data[16..];

    // Decrypt data
    let cipher = Cipher::aes_256_cbc();
    let decrypted = decrypt(cipher, &key, Some(iv), ciphertext)?;

    // Write Decrypted File
    fs::write(out_file, decrypted)
        .with_context(|| format!("Failed to write decrypted file: {}", out_file))?;

    println!("Decryption complete.");
    println!("  Decrypted data saved to: {}", out_file);

    Ok(())
}
