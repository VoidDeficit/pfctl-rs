#[cfg(target_os = "macos")]
mod macos {
    use std::fmt;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use crate::ffi::pfvar::pfsync_state_host;
    use crate::{Direction, Proto, ffi::pfvar::pfsync_state};
    use crate::{Error, ErrorInternal, Result};

    /// PF connection state created by a stateful rule
    #[derive(Clone)]
    pub struct State {
        sync_state: pfsync_state,
    }

    // Manually derive `Debug` since `pfsync_state` contains unions.
    impl fmt::Debug for State {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("State")
                .field("direction", &self.direction())
                .field("proto", &self.proto())
                .field("local_address", &self.local_address())
                .field("remote_address", &self.remote_address())
                .finish()
        }
    }

    impl State {
        /// Wrap a `pfsync_state` so that it can be accessed safely.
        ///
        /// # Safety
        ///
        /// All bytes in `sync_state` must be initialized.
        pub(crate) unsafe fn new(sync_state: pfsync_state) -> State {
            State { sync_state }
        }

        /// Return the direction for this state
        pub fn direction(&self) -> Result<Direction> {
            Direction::try_from(self.sync_state.direction)
        }

        /// Return the transport protocol for this state
        pub fn proto(&self) -> Result<Proto> {
            Proto::try_from(self.sync_state.proto)
        }

        /// Return the local socket address for this state
        pub fn local_address(&self) -> Result<SocketAddr> {
            // SAFETY: The address and port are initialized according to the contract of
            // `Self::new`.
            unsafe { parse_address(self.sync_state.af_lan, self.sync_state.lan) }
        }

        /// Return the remote socket address for this state
        pub fn remote_address(&self) -> Result<SocketAddr> {
            // SAFETY: The address and port are initialized according to the contract of
            // `Self::new`.
            unsafe { parse_address(self.sync_state.af_lan, self.sync_state.ext_lan) }
        }

        /// Return a reference to the inner `pfsync_state` state
        pub(crate) fn as_raw(&self) -> &pfsync_state {
            &self.sync_state
        }
    }

    /// Parse an IP address and port from a `pfsync_sync_host`, normally provided by
    /// `pfsync_state`.
    ///
    /// # Safety
    ///
    /// `host` must contain a valid address and a port:
    /// * If `family == PF_INET`, then `host.addr.pfa._v4addr` must be initialized.
    /// * If `family == PF_INET6`, then `host.addr.pfa._v6addr` must be initialized.
    /// * `host.xport.port` must always be initialized.
    unsafe fn parse_address(family: u8, host: pfsync_state_host) -> Result<SocketAddr> {
        let ip = match u32::from(family) {
            crate::ffi::pfvar::PF_INET => {
                // SAFETY: The caller has initialized this memory
                Ipv4Addr::from(u32::from_be(unsafe { host.addr.pfa._v4addr.s_addr })).into()
            }
            crate::ffi::pfvar::PF_INET6 => {
                // SAFETY: The caller has initialized this memory
                Ipv6Addr::from(unsafe { host.addr.pfa._v6addr.__u6_addr.__u6_addr8 }).into()
            }
            _ => return Err(Error::from(ErrorInternal::InvalidAddressFamily(family))),
        };

        // SAFETY: The caller has initialized this memory
        let port = u16::from_be(unsafe { host.xport.port });

        Ok(SocketAddr::new(ip, port))
    }

    #[cfg(test)]
    mod tests {
        use super::pfsync_state_host;
        use crate::{AddrFamily, state::macos::parse_address};
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

        #[test]
        fn test_parse_ipv4_address() {
            const EXPECTED_IP: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
            const EXPECTED_PORT: u16 = 12345;

            let mut host: pfsync_state_host = unsafe { std::mem::zeroed() };
            host.addr.pfa._v4addr.s_addr = u32::from_be_bytes(EXPECTED_IP.octets()).to_be();
            host.xport.port = EXPECTED_PORT.to_be();

            let family = u8::from(AddrFamily::Ipv4);

            let address = unsafe { parse_address(family, host) }.unwrap();
            assert_eq!(address, SocketAddr::new(EXPECTED_IP.into(), EXPECTED_PORT));
        }

        #[test]
        fn test_parse_ipv6_address() {
            const EXPECTED_IP: Ipv6Addr = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 0x7f);
            const EXPECTED_PORT: u16 = 12345;

            let mut host: pfsync_state_host = unsafe { std::mem::zeroed() };
            host.addr.pfa._v6addr.__u6_addr.__u6_addr8 = EXPECTED_IP.octets();
            host.xport.port = EXPECTED_PORT.to_be();

            let family = u8::from(AddrFamily::Ipv6);

            let address = unsafe { parse_address(family, host) }.unwrap();
            assert_eq!(address, SocketAddr::new(EXPECTED_IP.into(), EXPECTED_PORT));
        }
    }
}
#[cfg(target_os = "macos")]
pub use macos::State;

// FreeBSD's pf(4) does not expose the flat `pfsync_state` struct that macOS/OpenBSD have (with
// its `lan`/`gwy`/`ext_lan`/`ext_gwy` quad of hosts). Instead the ioctl surface
// (`DIOCGETSTATES` / `struct pfioc_states`) hands back `struct pfsync_state_1301`, which
// represents each state as a `key: [pfsync_state_key; 2]` pair: `key[0]` is the "wire" side
// (addresses/ports as seen on the network, i.e. `PF_SK_WIRE`) and `key[1]` is the "stack" side
// (post-NAT translation, if any, i.e. `PF_SK_STACK`). For a non-NAT'd state (the vast majority
// of what talpid-core's kill-switch cares about) wire and stack are identical. We treat
// `key[0].addr[0]/port[0]` as local and `key[0].addr[1]/port[1]` as remote, mirroring how
// macOS's `lan`/`ext_lan` pair is consumed by `Firewall::should_delete_state` in talpid-core
// (local = our side, remote = peer side). This is a best-effort mapping, not verified against
// live traffic yet -- see freebsd_notes.md. `_1301` (rather than `_1400`) is used because that's
// what a plain (non-`_v2`) `DIOCGETSTATES` call returns on FreeBSD 14.x.
#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::fmt;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use crate::ffi::pfvar::pfsync_state_1301;
    use crate::{Direction, Error, ErrorInternal, Proto, Result};

    /// PF connection state created by a stateful rule
    #[derive(Clone)]
    pub struct State {
        sync_state: pfsync_state_1301,
    }

    impl fmt::Debug for State {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("State")
                .field("direction", &self.direction())
                .field("proto", &self.proto())
                .field("local_address", &self.local_address())
                .field("remote_address", &self.remote_address())
                .finish()
        }
    }

    impl State {
        /// Wrap a `pfsync_state_1301` so that it can be accessed safely.
        ///
        /// # Safety
        ///
        /// All bytes in `sync_state` must be initialized.
        pub(crate) unsafe fn new(sync_state: pfsync_state_1301) -> State {
            State { sync_state }
        }

        /// Return the direction for this state
        pub fn direction(&self) -> Result<Direction> {
            Direction::try_from(self.sync_state.direction)
        }

        /// Return the transport protocol for this state
        pub fn proto(&self) -> Result<Proto> {
            Proto::try_from(self.sync_state.proto)
        }

        /// Return the local ("wire" key, index 0) socket address for this state
        pub fn local_address(&self) -> Result<SocketAddr> {
            // `pfsync_state_1301` is `#[repr(C, packed)]`, so fields must be copied out (not
            // referenced) before use.
            let key = self.sync_state.key[0];
            parse_address(self.sync_state.af, key.addr[0], key.port[0])
        }

        /// Return the remote ("wire" key, index 1) socket address for this state
        pub fn remote_address(&self) -> Result<SocketAddr> {
            let key = self.sync_state.key[0];
            parse_address(self.sync_state.af, key.addr[1], key.port[1])
        }

        /// Return a reference to the inner `pfsync_state_1301` state
        pub(crate) fn as_raw(&self) -> &pfsync_state_1301 {
            &self.sync_state
        }
    }

    /// Parse an IP address and port from a `pf_addr` + a big-endian port, as found in
    /// `pfsync_state_key`.
    fn parse_address(
        family: u8,
        addr: crate::ffi::pfvar::pf_addr,
        port_be: u16,
    ) -> Result<SocketAddr> {
        let ip = match u32::from(family) {
            crate::ffi::pfvar::PF_INET => {
                // SAFETY: `pf_addr`'s inner union is valid for either address family here;
                // `v4` reads the leading 4 bytes, which is where an AF_INET address lives.
                Ipv4Addr::from(u32::from_be(unsafe { addr.__bindgen_anon_1.v4.s_addr })).into()
            }
            crate::ffi::pfvar::PF_INET6 => {
                // SAFETY: see above; `v6` reads all 16 bytes of the union.
                Ipv6Addr::from(unsafe { addr.__bindgen_anon_1.v6.__u6_addr.__u6_addr8 }).into()
            }
            _ => return Err(Error::from(ErrorInternal::InvalidAddressFamily(family))),
        };

        Ok(SocketAddr::new(ip, u16::from_be(port_be)))
    }
}
#[cfg(target_os = "freebsd")]
pub use freebsd::State;
