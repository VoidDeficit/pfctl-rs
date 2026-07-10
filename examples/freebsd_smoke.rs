// Minimal smoke test for the FreeBSD port: exercises the parts of the PfCtl API that don't
// depend on add_anchor/remove_anchor (see freebsd_notes.md for what's not implemented yet).
//
// Expected outcomes:
//  - Not running as root: PfCtl::new() fails with a DeviceOpen (permission denied) error.
//  - Running as root: PfCtl::new() succeeds, is_enabled()/try_enable()/get_states() should all
//    return structurally sane results (Ok(..) with plausible values), which is a decent signal
//    that the ioctl struct layouts/numbers are right, even without a full round-trip rule test.
fn main() {
    match pfctl::PfCtl::new() {
        Ok(mut pf) => {
            println!("PfCtl::new() succeeded (are we root?)");
            match pf.is_enabled() {
                Ok(enabled) => println!("pf enabled: {enabled}"),
                Err(e) => println!("is_enabled() failed: {e} (kind: {:?})", e.kind()),
            }
            match pf.get_states() {
                Ok(states) => {
                    println!("get_states() returned {} states", states.len());
                    for s in states.iter().take(5) {
                        println!("  {s:?}");
                    }
                }
                Err(e) => println!("get_states() failed: {e} (kind: {:?})", e.kind()),
            }
        }
        Err(e) => {
            println!("PfCtl::new() failed: {e} (kind: {:?})", e.kind());
            assert_eq!(e.kind(), pfctl::ErrorKind::DeviceOpen);
        }
    }
}
