// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(target_os = "macos")]
use crate::AnchorKind;
#[cfg(target_os = "freebsd")]
use crate::RulesetKind;
use crate::{conversion::TryCopyTo, ffi, Error, ErrorInternal, PoolAddr, Result};
use std::{
    fs::{File, OpenOptions},
    mem,
    os::unix::io::RawFd,
};

/// The path to the PF device file this library will use to communicate with PF.
const PF_DEV_PATH: &str = "/dev/pf";

/// Open PF virtual device
pub fn open_pf() -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(PF_DEV_PATH)
        .map_err(|e| Error::from(ErrorInternal::DeviceOpen(PF_DEV_PATH, e)))
}

/// Add pool address using the pool ticket previously obtained via `get_pool_ticket()`
pub fn add_pool_address<A: Into<PoolAddr>>(
    fd: RawFd,
    pool_addr: A,
    pool_ticket: u32,
) -> Result<()> {
    let mut pfioc_pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pfioc_pooladdr>() };
    pfioc_pooladdr.ticket = pool_ticket;
    pool_addr.into().try_copy_to(&mut pfioc_pooladdr.addr)?;
    ioctl_guard!(ffi::pf_add_addr(fd, &mut pfioc_pooladdr))
}

/// Get pool ticket
pub fn get_pool_ticket(fd: RawFd) -> Result<u32> {
    let mut pfioc_pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pfioc_pooladdr>() };
    ioctl_guard!(ffi::pf_begin_addrs(fd, &mut pfioc_pooladdr))?;
    Ok(pfioc_pooladdr.ticket)
}

/// Only used by the (macOS-only) direct `DIOCCHANGERULE`-based `PfCtl::add_rule`/`add_nat_rule`/
/// `add_redirect_rule`/`add_scrub_rule` methods; FreeBSD lacks `PF_CHANGE_GET_TICKET`. The
/// transaction path (`Transaction::commit`, used by `set_rules`/`flush_rules`) gets its tickets
/// from `DIOCXBEGIN` instead and does not call this.
#[cfg(target_os = "macos")]
pub fn get_ticket(fd: RawFd, anchor: &str, kind: AnchorKind) -> Result<u32> {
    let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
    pfioc_rule.action = ffi::pfvar::PF_CHANGE_GET_TICKET as u32;
    pfioc_rule.rule.action = kind.into();
    copy_anchor_name(anchor, &mut pfioc_rule.anchor[..])?;
    ioctl_guard!(ffi::pf_change_rule(fd, &mut pfioc_rule))?;
    Ok(pfioc_rule.ticket)
}

pub fn copy_anchor_name(anchor: &str, destination: &mut [i8]) -> Result<()> {
    anchor
        .try_copy_to(destination)
        .map_err(|reason| Error::from(ErrorInternal::InvalidAnchorName(reason)))
}

/// Reads a NUL-terminated `c_char` buffer (as found in `pfioc_rule.anchor_call`, `pf_rule.
/// ifname`, etc.) as a `&str`. Used by the FreeBSD nvlist path (`nv.rs`) and by
/// `PfCtl::remove_anchor` to read back existing anchor-call rule names before re-adding them.
#[cfg(target_os = "freebsd")]
pub fn cstr_field(chars: &[std::os::raw::c_char]) -> &str {
    let bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(chars.as_ptr() as *const u8, chars.len()) };
    std::ffi::CStr::from_bytes_until_nul(bytes)
        .expect("C buffer without terminating null byte")
        .to_str()
        .expect("PF interface/anchor names are validated ASCII on the way in")
}

/// Opens a `DIOCXBEGIN` transaction scoped to a single `(anchor, ruleset_kind)` pair and also
/// fetches a pool ticket for it, mirroring what `pfctl(8)` itself does before a `DIOCADDRULENV`
/// call (`DIOCXBEGIN` -> `DIOCBEGINADDRS` -> one `DIOCADDRULENV` per rule -> `DIOCXCOMMIT`; see
/// `nv.rs`'s module docs). Returns `(transaction_ticket, pool_ticket)`.
///
/// FreeBSD-only: this is the nvlist path's equivalent of what `Transaction::commit` does
/// internally for the struct-based `DIOCADDRULE` path, exposed standalone here because
/// `add_anchor`/`remove_anchor` need to interleave it with `DIOCADDRULENV` calls rather than
/// `DIOCADDRULE` ones.
#[cfg(target_os = "freebsd")]
pub fn begin_ruleset_trans(fd: RawFd, anchor: &str, kind: RulesetKind) -> Result<(u32, u32)> {
    let mut pfioc_trans = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans>() };
    let mut element = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() };
    element.rs_num = kind.into();
    copy_anchor_name(anchor, &mut element.anchor[..])?;

    pfioc_trans.size = 1;
    pfioc_trans.esize = mem::size_of::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() as i32;
    pfioc_trans.array = &mut element;

    ioctl_guard!(ffi::pf_begin_trans(fd, &mut pfioc_trans))?;
    let pool_ticket = get_pool_ticket(fd)?;
    Ok((element.ticket, pool_ticket))
}

/// Commits the transaction `begin_ruleset_trans` opened. `ticket` must be the transaction
/// ticket it returned (the same value every `DIOCADDRULENV` call in between was given).
#[cfg(target_os = "freebsd")]
pub fn commit_ruleset_trans(fd: RawFd, anchor: &str, kind: RulesetKind, ticket: u32) -> Result<()> {
    let mut pfioc_trans = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans>() };
    let mut element = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() };
    element.rs_num = kind.into();
    element.ticket = ticket;
    copy_anchor_name(anchor, &mut element.anchor[..])?;

    pfioc_trans.size = 1;
    pfioc_trans.esize = mem::size_of::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() as i32;
    pfioc_trans.array = &mut element;

    ioctl_guard!(ffi::pf_commit_trans(fd, &mut pfioc_trans))
}
