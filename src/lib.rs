pub mod types;
use crate::types::error::Error;
use crate::types::log_proto::ProtocolType;
use crate::types::log_header::LogHeader;
use crate::types::log_data::LogData;
use crate::types::log_directory::LogDirectory;
use crate::types::search::SearchParams;

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
