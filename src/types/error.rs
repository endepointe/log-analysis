// default log path: /usr/local/zeek or /opt/zeek or custom/path/
// https://docs.zeek.org/en/master/quickstart.html#filesystem-walkthrough

#[derive(Debug, PartialEq, Eq)]
pub enum
ErrorType
{
    PathNotFound,
    PathPrefixUnspecified,
    ZeekProtocolNotFound,
    SearchInvalidStartDate,
    SearchInvalidEndDate,
    SearchInsufficientParams
}
pub type Error = ErrorType;

