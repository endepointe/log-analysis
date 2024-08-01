
use crate::zeek::zeek_log_proto::ZeekProtocol;
use std::collections::{BTreeMap, HashMap};

pub type LogTree = BTreeMap<ZeekProtocol, HashMap<String, HashMap<String, Vec<String>>>>;
