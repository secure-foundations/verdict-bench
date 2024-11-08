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
pub use firefox::{
    Environment as FirefoxEnvironment,
    ExecEnvironment as ExecFirefoxEnvironment,
    valid_chain as firefox_valid_chain,
    exec_valid_chain as exec_firefox_valid_chain,
};

use vstd::prelude::*;
use rspec::rspec;
use rspec_lib::*;

verus! {

rspec! {

use ExecCertificate as Certificate;
use ExecChromeEnvironment as ChromeEnvironment;
use ExecFirefoxEnvironment as FirefoxEnvironment;
use exec_chrome_valid_chain as chrome_valid_chain;
use exec_firefox_valid_chain as firefox_valid_chain;

pub enum Policy {
    Chrome(ChromeEnvironment),
    Firefox(FirefoxEnvironment),
}

pub open spec fn valid_chain(policy: &Policy, chain: &Seq<Certificate>, domain: &SpecString) -> bool {
    match policy {
        Policy::Chrome(env) => chrome_valid_chain(env, chain, domain),
        Policy::Firefox(env) => firefox_valid_chain(env, chain, domain),
    }
}

} // rspec!

} // verus!
