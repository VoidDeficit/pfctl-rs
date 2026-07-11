// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! FreeBSD-only. Serializes a populated [`ffi::pfvar::pf_rule`] into the `libnv` nvlist wire
//! format `DIOCADDRULENV` expects, and issues that ioctl.
//!
//! # Why this exists
//!
//! FreeBSD's pf(4) dropped `DIOCINSERTRULE`/`DIOCDELETERULE`/`PF_CHANGE_*` (the ioctls macOS
//! uses for anchor management), but *kept* `DIOCADDRULE` (struct-based, used by this crate's
//! `Transaction`/`set_rules` already). So why do we need a second, nvlist-based rule-adding
//! path here at all, instead of just using `DIOCADDRULE` for anchors too?
//!
//! Verified by `ktrace`/`kdump` against FreeBSD's own `pfctl(8)`: adding rules to a *named
//! anchor* (`pfctl -a <name> -f <file>`) goes `DIOCXBEGIN` -> `DIOCBEGINADDRS` ->
//! `DIOCADDRULENV` (once per rule) -> `DIOCXCOMMIT`, never touching struct-based
//! `DIOCADDRULE` at all. `DIOCADDRULE` still exists and this crate's `Transaction` already uses
//! it successfully -- for filling an anchor's ruleset via `pfioc_trans`, which is a different
//! code path in the kernel from "insert one more anchor rule into a parent ruleset" (what
//! `add_anchor` needs). We did not find a verified way to add anchor rules on FreeBSD via
//! `DIOCADDRULE`, so this follows what `pfctl(8)` itself does.
//!
//! # Field coverage
//!
//! The kernel's nvlist parser (`pf_nvrule_to_krule` in `sys/netpfil/pf/pf_nv.c`) requires the
//! vast majority of `struct pf_krule`'s fields to be present in the nvlist -- there is no
//! "send only what you set" shortcut, unlike the struct-based path where a `mem::zeroed`
//! `pf_rule` already has correct zero defaults for everything. This module supplies every
//! required key with a value read directly off an already-populated `ffi::pfvar::pf_rule`
//! (the exact same struct this crate's `Transaction::add_filter_rule` etc. build via
//! `TryCopyTo<pf_rule>`), so the nvlist encoding stays consistent with the already-verified
//! struct-based path by construction, rather than re-deriving field mappings independently.
//!
//! Fields this module does **not** attempt to round-trip because nothing in this crate's rule
//! types ever sets them (all confirmed zero/default on every `pf_rule` this crate builds):
//! `qname`/`pqname` (queueing), `tagname`/`match_tagname` (PF tagging), `overload_tblname`,
//! `os_fingerprint`, `rtableid`, the `timeout[]` array, `max_states`/`max_src_*` (state
//! limits), `prob` (probability matching), `divert`, `dnpipe`/`dnrpipe`/`dnflags` (dummynet).
//! They are sent as zero/empty, matching pf's "unset" defaults, exactly as the struct-based
//! path already does by zero-initializing `pf_rule` before filling in only the fields this
//! crate's `FilterRule`/`NatRule`/etc. builders expose.
//!
//! `rpool`'s `key`/`counter`/`tblidx`/`proxy_port`/`opts` are sent zeroed: the pool *address*
//! itself is registered separately via `DIOCBEGINADDRS`/`DIOCADDADDR` (see `utils`), same as
//! the struct-based path -- `rpool` in the rule nvlist only carries pf's internal round-robin
//! cursor state, which this crate has never populated on any platform.

use crate::{ffi, utils::cstr_field};
use libnv::libnv::{NvFlag, NvList};
use std::{mem, os::unix::io::RawFd, slice};

/// Builds the nvlist `pf_nvaddr_to_addr` expects: a single `"addr"` binary key holding a raw
/// `struct pf_addr`.
fn addr_nv(addr: &ffi::pfvar::pf_addr) -> NvList {
    let mut nvl = NvList::new(NvFlag::None).expect("nvlist_create");
    let bytes = unsafe {
        slice::from_raw_parts(
            (addr as *const ffi::pfvar::pf_addr) as *const u8,
            mem::size_of::<ffi::pfvar::pf_addr>(),
        )
    };
    nvl.insert_binary("addr", bytes).expect("insert_binary");
    nvl
}

/// Builds the nvlist `pf_nvaddr_wrap_to_addr_wrap` expects for a `pf_addr_wrap`.
fn addr_wrap_nv(wrap: &ffi::pfvar::pf_addr_wrap) -> NvList {
    let mut nvl = NvList::new(NvFlag::None).expect("nvlist_create");
    nvl.insert_number("type", wrap.type_ as u64)
        .expect("insert_number");
    nvl.insert_number("iflags", wrap.iflags as u64)
        .expect("insert_number");
    // PF_ADDR_DYNIFTL / PF_ADDR_TABLE carry their name in `v.ifname`/`v.tblname` instead of
    // `v.a.{addr,mask}`; this crate never constructs those variants (see `PF_ADDR_ADDRMASK`
    // usage in rule/mod.rs, the only `pf_addr_wrap.type_` this crate ever sets), so `v.a` is
    // always the active union member here.
    let (addr, mask) = unsafe { (wrap.v.a.addr, wrap.v.a.mask) };
    nvl.insert("addr", addr_nv(&addr)).expect("insert nvlist");
    nvl.insert("mask", addr_nv(&mask)).expect("insert nvlist");
    nvl
}

/// Builds the nvlist `pf_nvrule_addr_to_rule_addr` expects for a `pf_rule_addr` (src/dst).
fn rule_addr_nv(rule_addr: &ffi::pfvar::pf_rule_addr) -> NvList {
    let mut nvl = NvList::new(NvFlag::None).expect("nvlist_create");
    nvl.insert("addr", addr_wrap_nv(&rule_addr.addr))
        .expect("insert nvlist");
    nvl.insert_numbers(
        "port",
        &[rule_addr.port[0] as u64, rule_addr.port[1] as u64],
    )
    .expect("insert_numbers");
    nvl.insert_number("neg", rule_addr.neg as u64)
        .expect("insert_number");
    nvl.insert_number("port_op", rule_addr.port_op as u64)
        .expect("insert_number");
    nvl
}

/// Builds the nvlist `pf_nvrule_uid_to_rule_uid`/`pf_nvrule_gid_to_rule_gid` expect. Both
/// kernel-side parsers accept the identical shape (`"uid"`/`2`-element number array + `"op"`),
/// `pf_nvrule_gid_to_rule_gid` literally reuses the uid parser by pointer cast.
fn uid_like_nv(ids: [libc::uid_t; 2], op: u8, key: &str) -> NvList {
    let mut nvl = NvList::new(NvFlag::None).expect("nvlist_create");
    nvl.insert_numbers(key, &[ids[0] as u64, ids[1] as u64])
        .expect("insert_numbers");
    nvl.insert_number("op", op as u64).expect("insert_number");
    nvl
}

/// Builds the nvlist `pf_nvpool_to_pool` expects. `key`/`counter`/`tblidx`/`proxy_port`/`opts`
/// are always sent, all zeroed -- see module docs on why this crate never needs to populate
/// pf's pool round-robin state here.
fn pool_nv(pool: &ffi::pfvar::pf_pool) -> NvList {
    let mut nvl = NvList::new(NvFlag::None).expect("nvlist_create");
    let key_bytes = unsafe {
        slice::from_raw_parts(
            (&pool.key as *const ffi::pfvar::pf_poolhashkey) as *const u8,
            mem::size_of::<ffi::pfvar::pf_poolhashkey>(),
        )
    };
    nvl.insert_binary("key", key_bytes).expect("insert_binary");
    nvl.insert("counter", addr_nv(&pool.counter))
        .expect("insert nvlist");
    nvl.insert_number("tblidx", pool.tblidx as u64)
        .expect("insert_number");
    nvl.insert_numbers(
        "proxy_port",
        &[pool.proxy_port[0] as u64, pool.proxy_port[1] as u64],
    )
    .expect("insert_numbers");
    nvl.insert_number("opts", pool.opts as u64)
        .expect("insert_number");
    // "mape" is left unset: it is optional (kernel only reads it if present, see
    // `pf_nvpool_to_pool`'s `nvlist_exists_nvlist(nvl, "mape")` guard) and the kernel's own
    // `struct pf_pool` on FreeBSD 14.x has no `mape` member for a zeroed value to come from.
    nvl
}

/// Builds the top-level `"rule"` nvlist `pf_nvrule_to_krule` (sys/netpfil/pf/pf_nv.c) expects,
/// from an already-populated `pf_rule`. Every key read unconditionally there (i.e. every field
/// that isn't behind an `nvlist_exists_*` guard in the kernel parser) is supplied here, even
/// when the value is zero -- omitting a required key makes the kernel return `EINVAL`.
fn rule_nv(rule: &ffi::pfvar::pf_rule) -> NvList {
    let mut nvl = NvList::new(NvFlag::None).expect("nvlist_create");

    nvl.insert_number("nr", rule.nr as u64)
        .expect("insert_number");
    nvl.insert("src", rule_addr_nv(&rule.src))
        .expect("insert nvlist");
    nvl.insert("dst", rule_addr_nv(&rule.dst))
        .expect("insert nvlist");

    // Optional: only sent when non-empty (matches pfctl_add_rule's own "labels" array
    // behavior for one label; kernel also accepts singular "label" but "labels" is what
    // upstream pfctl(8) itself emits, so we match that instead of inventing our own encoding).
    let label = cstr_field(&rule.label);
    if !label.is_empty() {
        nvl.insert_strings("labels", [label])
            .expect("insert_strings");
    }

    nvl.insert_number("ridentifier", 0u64)
        .expect("insert_number");
    nvl.insert_string("ifname", cstr_field(&rule.ifname))
        .expect("insert_string");
    nvl.insert_string("qname", "").expect("insert_string");
    nvl.insert_string("pqname", "").expect("insert_string");
    nvl.insert_string("tagname", "").expect("insert_string");
    nvl.insert_string("match_tagname", "")
        .expect("insert_string");
    nvl.insert_string("overload_tblname", "")
        .expect("insert_string");

    nvl.insert("rpool", pool_nv(&rule.rpool))
        .expect("insert nvlist");

    nvl.insert_number("os_fingerprint", 0u64)
        .expect("insert_number");
    nvl.insert_number("rtableid", 0u64).expect("insert_number");
    // PFTM_MAX (sys/netpfil/pf/pf.h) = 25 timeout slots; all-zero means "use pf's global
    // defaults", matching what a zeroed struct-based `pf_rule.timeout` already means.
    const PFTM_MAX: usize = 25;
    nvl.insert_numbers("timeout", &[0u64; PFTM_MAX])
        .expect("insert_numbers");
    nvl.insert_number("max_states", 0u64)
        .expect("insert_number");
    nvl.insert_number("max_src_nodes", 0u64)
        .expect("insert_number");
    nvl.insert_number("max_src_states", 0u64)
        .expect("insert_number");
    nvl.insert_number("max_src_conn", 0u64)
        .expect("insert_number");
    nvl.insert_number("max_src_conn_rate.limit", 0u64)
        .expect("insert_number");
    nvl.insert_number("max_src_conn_rate.seconds", 0u64)
        .expect("insert_number");
    nvl.insert_number("prob", 0u64).expect("insert_number");
    nvl.insert_number("cuid", 0u64).expect("insert_number");
    nvl.insert_number("cpid", 0u64).expect("insert_number");

    nvl.insert_number("return_icmp", 0u64)
        .expect("insert_number");
    nvl.insert_number("return_icmp6", 0u64)
        .expect("insert_number");
    nvl.insert_number("max_mss", 0u64).expect("insert_number");
    nvl.insert_number("scrub_flags", 0u64)
        .expect("insert_number");

    nvl.insert("uid", uid_like_nv(rule.uid.uid, rule.uid.op, "uid"))
        .expect("insert nvlist");
    nvl.insert("gid", uid_like_nv(rule.gid.gid, rule.gid.op, "uid"))
        .expect("insert nvlist");

    nvl.insert_number("rule_flag", rule.rule_flag as u64)
        .expect("insert_number");
    nvl.insert_number("action", rule.action as u64)
        .expect("insert_number");
    nvl.insert_number("direction", rule.direction as u64)
        .expect("insert_number");
    nvl.insert_number("log", rule.log as u64)
        .expect("insert_number");
    nvl.insert_number("logif", 0u64).expect("insert_number");
    nvl.insert_number("quick", rule.quick as u64)
        .expect("insert_number");
    nvl.insert_number("ifnot", 0u64).expect("insert_number");
    nvl.insert_number("match_tag_not", 0u64)
        .expect("insert_number");
    nvl.insert_number("natpass", 0u64).expect("insert_number");

    nvl.insert_number("keep_state", rule.keep_state as u64)
        .expect("insert_number");
    nvl.insert_number("af", rule.af as u64)
        .expect("insert_number");
    nvl.insert_number("proto", rule.proto as u64)
        .expect("insert_number");
    nvl.insert_number("type", 0u64).expect("insert_number");
    nvl.insert_number("code", 0u64).expect("insert_number");
    nvl.insert_number("flags", rule.flags as u64)
        .expect("insert_number");
    nvl.insert_number("flagset", rule.flagset as u64)
        .expect("insert_number");
    nvl.insert_number("min_ttl", 0u64).expect("insert_number");
    nvl.insert_number("allow_opts", 0u64)
        .expect("insert_number");
    nvl.insert_number("rt", rule.rt as u64)
        .expect("insert_number");
    nvl.insert_number("return_ttl", 0u64)
        .expect("insert_number");
    nvl.insert_number("tos", 0u64).expect("insert_number");
    nvl.insert_number("set_tos", 0u64).expect("insert_number");

    nvl.insert_number("flush", 0u64).expect("insert_number");
    nvl.insert_number("prio", 0u64).expect("insert_number");
    nvl.insert_numbers("set_prio", &[0u64, 0u64])
        .expect("insert_numbers");

    // "divert" is left unset (optional; guarded by nvlist_exists_nvlist in the kernel parser).
    // This crate never populates `pf_rule.divert` on any platform.

    nvl
}

/// Issues `DIOCADDRULENV` to add `rule` to `anchor`'s ruleset (or, when `anchor_call` is
/// non-empty and `anchor` is the *parent* ruleset's name, to insert an anchor-call rule that
/// hands evaluation off to the sub-ruleset named `anchor_call` -- see `add_anchor` in lib.rs).
///
/// `ticket` comes from `DIOCXBEGIN` (the transaction this call is part of); `pool_ticket` comes
/// from `DIOCBEGINADDRS` (see `utils::get_pool_ticket`), fetched fresh per rule exactly as the
/// struct-based `Transaction::add_filter_rule` already does.
pub(crate) fn add_rule_nv(
    fd: RawFd,
    rule: &ffi::pfvar::pf_rule,
    anchor: &str,
    anchor_call: &str,
    ticket: u32,
    pool_ticket: u32,
) -> crate::Result<()> {
    let mut nvl = NvList::new(NvFlag::None).expect("nvlist_create");
    nvl.insert_number("ticket", ticket as u64)
        .expect("insert_number");
    nvl.insert_number("pool_ticket", pool_ticket as u64)
        .expect("insert_number");
    nvl.insert_string("anchor", anchor).expect("insert_string");
    nvl.insert_string("anchor_call", anchor_call)
        .expect("insert_string");
    nvl.insert("rule", rule_nv(rule)).expect("insert nvlist");

    let mut packed = nvl.pack().expect("nvlist_pack");
    let mut pfioc_nv = unsafe { mem::zeroed::<ffi::pfvar::pfioc_nv>() };
    pfioc_nv.data = packed.as_mut_ptr();
    pfioc_nv.len = packed.len();
    pfioc_nv.size = packed.len();

    ioctl_guard!(ffi::pf_add_rule_nv(fd, &mut pfioc_nv))
}
