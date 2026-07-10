// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{AddrFamily, Ip, Port};
use crate::{
    conversion::{CopyTo, TryCopyTo},
    ffi,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Endpoint {
    ip: Ip,
    port: Port,
}

impl Endpoint {
    pub fn new<IP: Into<Ip>, PORT: Into<Port>>(ip: IP, port: PORT) -> Self {
        Endpoint {
            ip: ip.into(),
            port: port.into(),
        }
    }

    pub fn ip(&self) -> Ip {
        self.ip
    }

    pub fn port(&self) -> Port {
        self.port
    }

    pub fn get_af(&self) -> AddrFamily {
        self.ip.get_af()
    }
}

impl From<Ip> for Endpoint {
    fn from(ip: Ip) -> Self {
        Endpoint::new(ip, Port::default())
    }
}

impl From<Port> for Endpoint {
    fn from(port: Port) -> Self {
        Endpoint::new(Ip::default(), port)
    }
}

impl From<Ipv4Addr> for Endpoint {
    fn from(ip: Ipv4Addr) -> Self {
        Self::from(Ip::from(ip))
    }
}

impl From<Ipv6Addr> for Endpoint {
    fn from(ip: Ipv6Addr) -> Self {
        Self::from(Ip::from(ip))
    }
}

impl From<IpAddr> for Endpoint {
    fn from(ip: IpAddr) -> Self {
        Self::from(Ip::from(ip))
    }
}

impl From<SocketAddrV4> for Endpoint {
    fn from(socket_addr: SocketAddrV4) -> Self {
        Endpoint::new(Ip::from(*socket_addr.ip()), Port::from(socket_addr.port()))
    }
}

impl From<SocketAddrV6> for Endpoint {
    fn from(socket_addr: SocketAddrV6) -> Self {
        Endpoint::new(Ip::from(*socket_addr.ip()), Port::from(socket_addr.port()))
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(socket_addr: SocketAddr) -> Self {
        match socket_addr {
            SocketAddr::V4(addr) => Endpoint::from(addr),
            SocketAddr::V6(addr) => Endpoint::from(addr),
        }
    }
}

#[cfg(target_os = "macos")]
impl TryCopyTo<ffi::pfvar::pf_rule_addr> for Endpoint {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_rule_addr: &mut ffi::pfvar::pf_rule_addr) -> crate::Result<()> {
        self.ip.copy_to(&mut pf_rule_addr.addr);
        self.port
            .try_copy_to(unsafe { &mut pf_rule_addr.xport.range })?;
        Ok(())
    }
}

// FreeBSD's `pf_rule_addr` has no `xport` union (there is no `pf_rule_xport` type at all on
// FreeBSD); the port range is inlined directly as `port: [u16; 2]` + `port_op: u8`, equivalent
// in shape to macOS's `pf_port_range`. Write to those fields directly instead of going through
// `Port`'s `TryCopyTo<pf_port_range>` impl, which targets a type that doesn't exist here.
#[cfg(target_os = "freebsd")]
impl TryCopyTo<ffi::pfvar::pf_rule_addr> for Endpoint {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_rule_addr: &mut ffi::pfvar::pf_rule_addr) -> crate::Result<()> {
        self.ip.copy_to(&mut pf_rule_addr.addr);
        match self.port {
            Port::Any => {
                pf_rule_addr.port_op = ffi::pfvar::PF_OP_NONE as u8;
                pf_rule_addr.port[0] = 0;
                pf_rule_addr.port[1] = 0;
            }
            Port::One(port, modifier) => {
                pf_rule_addr.port_op = modifier.into();
                pf_rule_addr.port[0] = port.to_be();
                pf_rule_addr.port[1] = 0;
            }
            Port::Range(start_port, end_port, modifier) => {
                if start_port > end_port {
                    return Err(crate::Error::from(crate::ErrorInternal::InvalidPortRange));
                }
                pf_rule_addr.port_op = modifier.into();
                pf_rule_addr.port[0] = start_port.to_be();
                pf_rule_addr.port[1] = end_port.to_be();
            }
        }
        Ok(())
    }
}
