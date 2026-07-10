// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Error, ErrorInternal, conversion::TryCopyTo, ffi};

// Port range representation
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Port {
    #[default]
    Any,
    One(u16, PortUnaryModifier),
    Range(u16, u16, PortRangeModifier),
}

impl From<u16> for Port {
    fn from(port: u16) -> Self {
        Port::One(port, PortUnaryModifier::Equal)
    }
}

#[cfg(target_os = "macos")]
impl TryCopyTo<ffi::pfvar::pf_port_range> for Port {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_port_range: &mut ffi::pfvar::pf_port_range) -> crate::Result<()> {
        match *self {
            Port::Any => {
                pf_port_range.op = ffi::pfvar::PF_OP_NONE as u8;
                pf_port_range.port[0] = 0;
                pf_port_range.port[1] = 0;
            }
            Port::One(port, modifier) => {
                pf_port_range.op = modifier.into();
                // convert port range to network byte order
                pf_port_range.port[0] = port.to_be();
                pf_port_range.port[1] = 0;
            }
            Port::Range(start_port, end_port, modifier) => {
                if start_port > end_port {
                    return Err(Error::from(ErrorInternal::InvalidPortRange));
                }
                pf_port_range.op = modifier.into();
                // convert port range to network byte order
                pf_port_range.port[0] = start_port.to_be();
                pf_port_range.port[1] = end_port.to_be();
            }
        }
        Ok(())
    }
}

// FreeBSD's `pfvar.h` has no `pf_port_range` type at all; this crate's only two consumers of
// `TryCopyTo<pf_port_range>` are `Endpoint`'s `pf_rule_addr` impl (see rule/endpoint.rs, which
// has its own FreeBSD-specific impl writing directly to `pf_rule_addr.port`/`port_op`) and no
// one else. So there is intentionally no FreeBSD impl of this trait for `pf_port_range` --
// nothing needs it.

#[cfg(target_os = "macos")]
impl TryCopyTo<ffi::pfvar::pf_pool> for Port {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_pool: &mut ffi::pfvar::pf_pool) -> crate::Result<()> {
        match *self {
            Port::Any => {
                pf_pool.port_op = ffi::pfvar::PF_OP_NONE as u8;
                pf_pool.proxy_port[0] = 0;
                pf_pool.proxy_port[1] = 0;
            }
            Port::One(port, modifier) => {
                pf_pool.port_op = modifier.into();
                pf_pool.proxy_port[0] = port;
                pf_pool.proxy_port[1] = 0;
            }
            Port::Range(start_port, end_port, modifier) => {
                if start_port > end_port {
                    return Err(Error::from(ErrorInternal::InvalidPortRange));
                }
                pf_pool.port_op = modifier.into();
                pf_pool.proxy_port[0] = start_port;
                pf_pool.proxy_port[1] = end_port;
            }
        }
        Ok(())
    }
}

// FreeBSD's `pf_pool` has no `port_op` field (only macOS/OpenBSD's does) -- the port-operator
// concept (equal/range/exclusive/...) for NAT/redirect proxy ports doesn't exist in FreeBSD's
// struct at all, only a plain `proxy_port: [u16; 2]`. This is best-effort: `Port::Any` and
// `Port::One` both just set `proxy_port[0]` (with `[1]` left at 0, matching "no explicit second
// bound"), and `Port::Range` sets both bounds; there is no way to express the
// exclusive/inclusive/except distinction `PortRangeModifier` carries. Not used by
// `talpid-core`'s firewall backend today (only reachable via `NatEndpoint`, which is only
// exercised by the macOS 14.6-15.1 NAT_WORKAROUND path, itself gated `target_os = "macos"` in
// `macos.rs`), but must still compile since `port.rs` is compiled unconditionally.
#[cfg(target_os = "freebsd")]
impl TryCopyTo<ffi::pfvar::pf_pool> for Port {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_pool: &mut ffi::pfvar::pf_pool) -> crate::Result<()> {
        match *self {
            Port::Any => {
                pf_pool.proxy_port[0] = 0;
                pf_pool.proxy_port[1] = 0;
            }
            Port::One(port, _modifier) => {
                pf_pool.proxy_port[0] = port;
                pf_pool.proxy_port[1] = 0;
            }
            Port::Range(start_port, end_port, _modifier) => {
                if start_port > end_port {
                    return Err(Error::from(ErrorInternal::InvalidPortRange));
                }
                pf_pool.proxy_port[0] = start_port;
                pf_pool.proxy_port[1] = end_port;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortUnaryModifier {
    Equal,
    NotEqual,
    Greater,
    Less,
    GreaterOrEqual,
    LessOrEqual,
}

impl From<PortUnaryModifier> for u8 {
    fn from(modifier: PortUnaryModifier) -> Self {
        match modifier {
            PortUnaryModifier::Equal => ffi::pfvar::PF_OP_EQ as u8,
            PortUnaryModifier::NotEqual => ffi::pfvar::PF_OP_NE as u8,
            PortUnaryModifier::Greater => ffi::pfvar::PF_OP_GT as u8,
            PortUnaryModifier::Less => ffi::pfvar::PF_OP_LT as u8,
            PortUnaryModifier::GreaterOrEqual => ffi::pfvar::PF_OP_GE as u8,
            PortUnaryModifier::LessOrEqual => ffi::pfvar::PF_OP_LE as u8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortRangeModifier {
    Exclusive,
    Inclusive,
    Except,
}

impl From<PortRangeModifier> for u8 {
    fn from(modifier: PortRangeModifier) -> Self {
        match modifier {
            PortRangeModifier::Exclusive => ffi::pfvar::PF_OP_IRG as u8,
            PortRangeModifier::Inclusive => ffi::pfvar::PF_OP_RRG as u8,
            PortRangeModifier::Except => ffi::pfvar::PF_OP_XRG as u8,
        }
    }
}
