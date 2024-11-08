mod common;
mod chrome;
mod firefox;

pub use common::*;
pub use chrome::{
    Environment as ChromeEnvironment,
    ExecEnvironment as ExecChromeEnvironment,
    valid_chain as chrome_valid_chain,
    exec_valid_chain as exec_chrome_valid_chain,
};

use vstd::prelude::*;
use rspec::rspec;
use rspec_lib::*;

verus! {

rspec! {

use ExecChromeEnvironment as ChromeEnvironment;
use ExecCertificate as Certificate;
use exec_chrome_valid_chain as chrome_valid_chain;

pub enum Policy {
    Chrome(ChromeEnvironment),
}

pub open spec fn valid_chain(policy: &Policy, chain: &Seq<Certificate>, domain: &SpecString) -> bool {
    match policy {
        Policy::Chrome(env) => chrome_valid_chain(env, chain, domain),
    }
}

} // rspec!

} // verus!
