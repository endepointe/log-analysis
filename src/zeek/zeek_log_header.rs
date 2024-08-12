use serde::{Serialize, Deserialize};
#[derive(Debug,Clone,PartialEq,Eq, Serialize, Deserialize)]
pub struct 
ZeekLogHeader
{
    pub separator: char,
    pub set_separator: String,
    pub empty_field: String,
    pub unset_field: String,
    pub path: String, 
    pub open: String,
    pub fields: Vec<String>,
    pub types: Vec<String>,
}
