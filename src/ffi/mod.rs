// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use ioctl_sys::ioctl;

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
#[cfg(target_os = "macos")]
#[path = "pfvar_macos.rs"]
pub mod pfvar;

// FreeBSD's <net/pfvar.h> is generated from a newer/different pf(4) codebase than macOS's
// (which tracks upstream OpenBSD pf closely). Bindings were generated with:
//   bindgen --allowlist-type pf_status --allowlist-type pfioc_rule \
//       --allowlist-type pfioc_pooladdr --allowlist-type pfioc_trans \
//       --allowlist-type pfioc_states --allowlist-type pfioc_state_kill \
//       --allowlist-type pfioc_iface --allowlist-var 'PF_.*' \
//       --allowlist-var 'PFRULE_.*' --default-enum-style rust \
//       -o src/ffi/pfvar_freebsd.rs /usr/include/net/pfvar.h -- -DPRIVATE -I/usr/include
// See freebsd_notes.md for the struct-level differences from macOS that this crate's code
// has to account for.
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
#[cfg(target_os = "freebsd")]
#[path = "pfvar_freebsd.rs"]
pub mod pfvar;

pub mod tcp {
    use std::os::raw::c_uint;

    // exports from <netinet/tcp.h>
    pub const TH_FIN: c_uint = 0x01;
    pub const TH_SYN: c_uint = 0x02;
    pub const TH_RST: c_uint = 0x04;
    pub const TH_PSH: c_uint = 0x08;
    pub const TH_ACK: c_uint = 0x10;
    pub const TH_URG: c_uint = 0x20;
    pub const TH_ECE: c_uint = 0x40;
    pub const TH_CWR: c_uint = 0x80;
}

// The definitions of the ioctl calls come from pfvar.h. Look for the comment "ioctl operations"
// The documentation describing the order of calls and accepted parameters can be found at:
// http://man.openbsd.org/pf.4
//
// ioctl command numbers (the b'D' group + number) are identical between macOS and FreeBSD for
// every operation below -- verified against a FreeBSD 14.3-RELEASE /usr/include/net/pfvar.h.
// The one difference is DIOCINSERTRULE/DIOCDELETERULE (27/28), which FreeBSD's pf(4) dropped
// entirely (header comment: "XXX cut 26 - 28"), along with the PF_CHANGE_* constants that
// DIOCCHANGERULE's macOS callers rely on. Those two ioctls, and the anchor add/remove code that
// depends on them, are therefore macOS-only here; see anchor management notes in lib.rs.
// DIOCSTART
ioctl!(none pf_start with b'D', 1);
// DIOCSTOP
ioctl!(none pf_stop with b'D', 2);
// DIOCADDRULE
ioctl!(readwrite pf_add_rule with b'D', 4; pfvar::pfioc_rule);
// DIOCADDRULENV (FreeBSD only; shares ioctl base number 4 with DIOCADDRULE but a different
// payload struct/size, which BSD's ioctl encoding disambiguates -- see pfvar.h). This is how
// FreeBSD's own pfctl(8) adds rules to a *named anchor's* ruleset (verified via ktrace); the
// struct-based DIOCADDRULE above is only used by this crate's `Transaction`/`set_rules` path,
// which operates tickets/tickets the same way on both OSes.
#[cfg(target_os = "freebsd")]
ioctl!(readwrite pf_add_rule_nv with b'D', 4; pfvar::pfioc_nv);
// DIOCGETRULES
ioctl!(readwrite pf_get_rules with b'D', 6; pfvar::pfioc_rule);
// DIOCGETRULE
ioctl!(readwrite pf_get_rule with b'D', 7; pfvar::pfioc_rule);
// DIOCCLRSTATES
ioctl!(readwrite pf_clear_states with b'D', 18; pfvar::pfioc_state_kill);
// DIOCGETSTATUS
ioctl!(readwrite pf_get_status with b'D', 21; pfvar::pf_status);
// DIOCGETSTATES
ioctl!(readwrite pf_get_states with b'D', 25; pfvar::pfioc_states);
// DIOCCHANGERULE (macOS only -- see comment above; FreeBSD has the ioctl but not the PF_CHANGE_*
// verbs pfctl-rs's macOS code relies on)
#[cfg(target_os = "macos")]
ioctl!(readwrite pf_change_rule with b'D', 26; pfvar::pfioc_rule);
// DIOCINSERTRULE (macOS/OpenBSD only, removed on FreeBSD)
#[cfg(target_os = "macos")]
ioctl!(readwrite pf_insert_rule with b'D', 27; pfvar::pfioc_rule);
// DIOCDELETERULE (macOS/OpenBSD only, removed on FreeBSD)
#[cfg(target_os = "macos")]
ioctl!(readwrite pf_delete_rule with b'D', 28; pfvar::pfioc_rule);
// DIOCKILLSTATES
ioctl!(readwrite pf_kill_states with b'D', 41; pfvar::pfioc_state_kill);
// DIOCBEGINADDRS
ioctl!(readwrite pf_begin_addrs with b'D', 51; pfvar::pfioc_pooladdr);
// DIOCADDADDR
ioctl!(readwrite pf_add_addr with b'D', 52; pfvar::pfioc_pooladdr);
// DIOCXBEGIN
ioctl!(readwrite pf_begin_trans with b'D', 81; pfvar::pfioc_trans);
// DIOCXCOMMIT
ioctl!(readwrite pf_commit_trans with b'D', 82; pfvar::pfioc_trans);
// DIOCSETIFFLAG
ioctl!(readwrite pf_set_iface_flag with b'D', 89; pfvar::pfioc_iface);
// DIOCCLRIFFLAG
ioctl!(readwrite pf_clear_iface_flag with b'D', 90; pfvar::pfioc_iface);
