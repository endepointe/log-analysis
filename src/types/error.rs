// default log path: /usr/local/zeek or /opt/zeek or custom/path/
// https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough

#[derive(Debug, PartialEq, Eq)]
pub enum
ErrorType
{
    Unspecified,
    PathNotFound,
    PathPrefixUnspecified,
    ZeekProtocolNotFound,
    SearchInvalidStartDate,
    SearchInvalidEndDate,
    SearchInsufficientParams,
    NoLogHeader,
}
pub type Error = ErrorType;

