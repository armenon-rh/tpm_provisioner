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

fn main() -> Result<()> {
    provision::run()
}
