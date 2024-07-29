pub mod types;
pub mod zeek;

use crate::types::error::Error;
use crate::zeek::zeek_log_proto::ZeekProtocol;
use crate::zeek::zeek_log::ZeekLog;
use crate::zeek::zeek_log_directory::ZeekLogDirectory;
use crate::zeek::zeek_search_params::ZeekSearchParams;

// May use for data hits
fn 
increment<'a>(val: &'a mut u32)
{
    *val += 1;
}

fn 
print_val<'a>(val: &'a u32)
{
    println!("print_val : val is {}",val);
}


#[cfg(feature = "ip2location")]
pub fn ip2location() 
{
    dbg!("log_analysis::ip2location()");
}
