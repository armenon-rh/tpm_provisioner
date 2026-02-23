// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (c) 2026 Red Hat, Inc.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]

pub mod provision;
pub mod tcg;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tpm_provisioner")]
#[command(about = "A tool for TPM provisioning and key wrapping", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Provision the TPM with EK certificate
    Provision,
    /// Encrypt a file and generate a DEK
    Encrypt {
        /// Input file path
        #[arg(short, long)]
        input: String,
        /// Output file path for encrypted data
        #[arg(long)]
        out_file: String,
        /// Output file path for the DEK
        #[arg(long)]
        out_key: String,
    },
    /// Wrap a key using the KBS
    Wrap {
        /// Input key file path (DEK)
        #[arg(short, long)]
        input_key: String,
        /// KBS URL
        #[arg(long)]
        url: String,
        /// Output file path for wrapped key
        #[arg(short, long)]
        output: String,
    },
    /// Unwrap a key using the KBS
    Unwrap {
        /// Input wrapped key file path
        #[arg(short, long)]
        input_file: String,
        /// KBS URL
        #[arg(long)]
        url: String,
        /// Output file path for unwrapped key (DEK)
        #[arg(short, long)]
        output: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Provision => {
            provision::run()?;
        }
        Commands::Encrypt {
            input,
            out_file,
            out_key,
        } => {
            println!("Encrypting {} -> {} (key: {})", input, out_file, out_key);
            // TODO: Implement encryption
        }
        Commands::Wrap {
            input_key,
            url,
            output,
        } => {
            println!("Wrapping {} via {} -> {}", input_key, url, output);
            // TODO: Implement wrapping
        }
        Commands::Unwrap {
            input_file,
            url,
            output,
        } => {
            println!("Unwrapping {} via {} -> {}", input_file, url, output);
            // TODO: Implement unwrapping
        }
    }
    Ok(())
}
