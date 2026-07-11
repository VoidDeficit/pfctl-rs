// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Live functional test for the FreeBSD `add_anchor`/`remove_anchor`/`set_rules` path (the
//! nvlist-based `DIOCADDRULENV` machinery in `src/nv.rs`).
//!
//! This only prints what it did; the actual verification (that `pfctl -a <anchor> -sr` sees the
//! rule, and sees nothing after cleanup) is done from the shell script that invokes this, since
//! it needs to shell out to `pfctl(8)` between steps.
//!
//! Steps, selected by argv[1]:
//!   add    - add the anchor + one simple filter rule to it, then exit (leaves state behind)
//!   remove - remove the anchor, then exit
//! With no argument: runs add, then remove, back to back (for a quick non-shell-verified smoke
//! check that nothing panics/errors).

use pfctl::{AnchorChange, AnchorKind, FilterRuleBuilder, PfCtl};
use std::env;

const ANCHOR_NAME: &str = "os-mullvad-test";

fn add(pf: &mut PfCtl) {
    pf.try_add_anchor(ANCHOR_NAME, AnchorKind::Filter)
        .expect("add_anchor failed");
    println!("add_anchor({ANCHOR_NAME}, Filter) ok");

    let rule = FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .interface("lo0")
        .build()
        .expect("failed to build rule");

    let mut change = AnchorChange::new();
    change.set_filter_rules(vec![rule]);
    pf.set_rules(ANCHOR_NAME, change)
        .expect("set_rules failed");
    println!("set_rules({ANCHOR_NAME}, [pass on lo0]) ok");
}

fn remove(pf: &mut PfCtl) {
    // Mirrors talpid-core's reset_policy: clear the anchor's own rule content first, then
    // remove the anchor-call rule pointing to it.
    pf.flush_rules(ANCHOR_NAME, pfctl::RulesetKind::Filter)
        .expect("flush_rules failed");
    println!("flush_rules({ANCHOR_NAME}) ok");

    pf.try_remove_anchor(ANCHOR_NAME, AnchorKind::Filter)
        .expect("remove_anchor failed");
    println!("remove_anchor({ANCHOR_NAME}, Filter) ok");
}

fn main() {
    let mut pf = PfCtl::new().expect("Unable to connect to PF (are we root?)");
    pf.try_enable().expect("try_enable failed");

    match env::args().nth(1).as_deref() {
        Some("add") => add(&mut pf),
        Some("remove") => remove(&mut pf),
        _ => {
            add(&mut pf);
            remove(&mut pf);
        }
    }
}
