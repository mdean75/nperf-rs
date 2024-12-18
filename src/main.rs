// Copyright (c) 2023 Ravi V <ravi.vantipalli@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Copyright 2024 Mike DeAngelo
// Based on work by Ravi Vantipalli.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # nperf
//!
//! `nperf` is a network performance measurement tool for TCP/UDP/QUIC protocols. Similar to iperf3 in usage.
//!
//! ## Usage
//! More options available via help.
//!
//! ### Server
//! Binds to [::]:8080 by default
//! ```bash
//! cargo run -- -s
//! ```
//!
//! ### Client
//! Connects to 127.0.0.1:8080 by default and tests TCP streams
//! ```bash
//! cargo run --
//! cargo run -- -c 127.0.0.1
//! ```
//!
//! Test UDP performance
//! ```bash
//! cargo run -- -u
//! ```
//!
//! Test QUIC performance
//! ```bash
//! cargo run -- -q
//! '''
//!
//! Test with parallel streams using -P, period to test with -t
//! ```bash
//! cargo run -- -u -P 2 -t 30
//! ```
//!

use futures::executor::block_on;
use std::io;
use std::process::exit;
use env_logger::Target;
use log::LevelFilter;
use crate::client::ClientImpl;
use crate::params::PerfMode;
use crate::server::ServerImpl;
use crate::test::Test;

#[doc(hidden)]
mod client;
#[doc(hidden)]
mod metrics;
#[doc(hidden)]
mod net;
#[doc(hidden)]
mod noprotection;
#[doc(hidden)]
mod params;
#[doc(hidden)]
mod quic;
#[doc(hidden)]
mod server;
#[doc(hidden)]
mod tcp;
#[doc(hidden)]
mod test;
#[doc(hidden)]
mod tls;
#[doc(hidden)]
mod udp;

#[doc(hidden)]
fn main() -> io::Result<()> {
    env_logger::builder()
        .target(Target::Stdout)
        .filter_level(LevelFilter::Info)
        .format_timestamp_micros()
        .init();
    let param = params::parse_args().unwrap();

    match param.mode {
        PerfMode::SERVER => loop {
            let mut test = Test::from(&param);
            let mut server = ServerImpl::new(&param)?;
            let run = server.run(&mut test);
            match block_on(run) {
                Ok(_) => (),
                Err(e) => println!("Error: {}, restarting", e.to_string()),
            }
            test.reset();
        },
        PerfMode::CLIENT => {
            let test = Test::from(&param);
            let mut client = ClientImpl::new(&param)?;
            let run = client.run(test);
            match block_on(run) {
                Ok(_) => exit(0),
                Err(e) => {
                    println!("Error: {}, exiting", e.to_string());
                    exit(1);
                }
            }
        }
    }
}
