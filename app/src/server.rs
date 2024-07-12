// now learn how this all works
use async_graphql::{Schema, Context, Object, 
    ComplexObject, SimpleObject, Request, Result, 
    EmptyMutation, EmptySubscription
};
use async_graphql_actix_web::{GraphQLRequest, GraphQLResponse};
use actix_web::{web, App, HttpServer, Responder};
use std::fs::File;
use std::io::{self, Read};
use flate2::read::GzDecoder;
use std::io::Write;
use std::sync::Mutex;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

struct AppState 
{
    visits: Mutex<i32>,
}

struct LogInfo
{
    types: Mutex<std::collections::HashSet<String>>
}

struct Query;
#[Object]
impl Query 
{
    async fn zeeklogs(&self, _ctx: &Context<'_>) -> Result<String> 
    {
        println!("ctx: {:?}", _ctx.data::<String>());
        let path = "zeek-test-logs/2024-07-03/ssh.02:00:00-03:00:00.log.gz";
        let output = std::process::Command::new("zcat")
            .arg(path)
            .output()
            .expect("failed to execute process");
        let output = std::str::from_utf8(&output.stdout).unwrap();
        Ok(output.to_string())
    }
    async fn zeekdata(&self, _ctx: &Context<'_>) -> Result<ZeekData> 
    {
        Ok(ZeekData { name: "dns".to_string(), src_ip: "127.0.0.1".to_string() })
    }
}

#[derive(SimpleObject)]
#[graphql(complex)]
struct ZeekData 
{
    name: String,
    src_ip: String,
}

#[ComplexObject]
impl ZeekData 
{
    async fn source_ip(&self) -> String 
    {
        self.src_ip.clone()
    }
    async fn log_name(&self) -> String 
    {
        self.name.clone()
    }
}

#[derive(Debug,Clone)]
struct LogHeader
{
    separator: char,
    set_separator: String,
    empty_field: String,
    unset_field: String,
    path: String, // could turn this into a list to store multiple dates
    open: String,
    fields: Vec<String>,
    types: Vec<String>,
}
impl LogHeader
{
    fn set_header(p : &std::path::Path) -> Self 
    {
        let output = std::process::Command::new("zcat")
            .arg(&p)
            .output()
            .expect("failed to zcat the log file");
        let log_header = output.stdout;

        let mut pos : u8 = 0;
        let mut separator : char = ' ';
        let mut set_separator = String::new();
        let mut empty_field = String::new();
        let mut unset_field = String::new();
        let mut path = String::new();
        let mut open = String::new();
        let mut fields = Vec::<String>::new();
        let mut types = Vec::<String>::new();

        match std::str::from_utf8(&log_header) 
        {
            Ok(v) => {
                let mut buffer = String::new();
                for c in v.chars() {
                    if c == '\n' { 
                        match pos 
                        {
                            0 => {
                                let result = buffer.split(' ').collect::<Vec<&str>>()[1].strip_prefix("\\x");
                                let result = u8::from_str_radix(result.unwrap(), 16)
                                    .expect("LOG_SEPARATER_CHAR: ");
                                separator = char::from(result);
                            }
                            1 => {
                                set_separator = buffer.split(separator).collect::<Vec<_>>()[1].to_string();
                            }
                            2 => {
                                empty_field = buffer.split(separator).collect::<Vec<_>>()[1].to_string();
                            }
                            3 => {
                                unset_field = buffer.split(separator).collect::<Vec<_>>()[1].to_string();
                            }
                            4 => {
                                path = buffer.split(separator).collect::<Vec<_>>()[1].to_string();
                            }
                            5 => {
                                open = buffer.split(separator).collect::<Vec<_>>()[1].to_string();
                            }
                            6 => {
                                let s = buffer.split(separator).collect::<Vec<_>>();
                                for i in 1..s.len() 
                                {
                                    fields.push(s[i].to_string());
                                }
                            }
                            7 => {
                                let s = buffer.split(separator).collect::<Vec<_>>();
                                for i in 1..s.len() 
                                {
                                    types.push(s[i].to_string());
                                }
                            }
                            _ => {break;}
                        }
                        buffer.clear();
                        pos += 1; 
                        continue; // ignore the newline char.
                    } 
                    buffer.push(c);
                }
            }
            Err(e) => {
                eprintln!("{}",e.valid_up_to());
            }
        }

        LogHeader {
            separator,
            set_separator,
            empty_field,
            unset_field,
            path,
            open,
            fields,
            types,
        }
    }
    fn get_types(&self) -> &Vec<String>
    {
        &self.types
    }
    fn get_fields(&self) -> &Vec<String>
    {
        &self.fields
    }
}

#[derive(Debug)]
struct LogData<'a> 
{
    header: &'a LogHeader,
    data: std::collections::HashMap<&'a str, Vec<&'a str>>,
}
impl<'a> LogData<'a>
{
    fn new(h: &'a LogHeader) -> Self
    {
        let fields = h.get_fields();
        let mut f = std::collections::HashMap::<&'a str, Vec<&'a str>>::new();
        for field in fields
        {
            f.insert(&field, Vec::<&'a str>::new());
        }
        LogData {header: h, data: f}
    }
    fn add_field_entry(&mut self, key: &'a str, val: &'a str)
    {
        self.data.entry(key).or_insert(Vec::new()).push(val);
    }
}

type AppSchema = Schema<Query, EmptyMutation, EmptySubscription>;

#[actix_web::main]
async fn main() -> std::io::Result<()> 
{
    let mut ssl_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    ssl_builder.set_private_key_file("key.pem", SslFiletype::PEM).unwrap();
    ssl_builder.set_certificate_chain_file("cert.pem").unwrap();

    let visits = web::Data::new(AppState { visits: 1000.into() });
    let log_info = web::Data::new(LogInfo { types: std::collections::HashSet::new().into() });

    let schema = Schema::build(Query, EmptyMutation, EmptySubscription)
        .data("data_hello".to_string())
        .finish();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(schema.clone()))
            .app_data(visits.clone())
            .app_data(log_info.clone())
            .service(web::resource("/hello").route(web::get().to(hello_handler)))
            .service(web::resource("/graphql").route(web::post().to(graphql_handler)))
    })
    .bind_openssl("0.0.0.0:8080", ssl_builder)?
    .run()
    .await
}

async fn hello_handler(schema: web::Data<AppState>) -> impl Responder 
{
    println!("ctx: {:?}", schema.visits);
    let mut visits = schema.visits.lock().unwrap();
    *visits += 1;
    format!("Hello, world! Visits: {}\n", visits)
}

async fn graphql_handler(schema: web::Data<AppSchema>, req: GraphQLRequest) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

fn increment<'a>(val: &'a mut u32)
{
    *val += 1;
}

fn print_val<'a>(val: &'a u32)
{
    println!("print_val : val is {}",val);
}

mod tests 
{
    #[test]
    fn test_graphql() 
    {
        let res = std::process::Command::new("curl")
            .arg("--cacert")
            .arg("cert.pem")
            .arg("-X")
            .arg("POST")
            .arg("https://localhost:8080/graphql")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(r#"{"query":"{ zeekdata { logName sourceIp } }"}"#)
            .output()
            .expect("failed to execute process");
        let output = std::str::from_utf8(&res.stdout).unwrap();
        println!("{}", output);

        let res = std::process::Command::new("curl")
            .arg("--cacert")
            .arg("cert.pem")
            .arg("-X")
            .arg("POST")
            .arg("https://localhost:8080/graphql")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(r#"{"query":"{ zeekdata { logName } }"}"#)
            .output()
            .expect("failed to execute process");
        let output = std::str::from_utf8(&res.stdout).unwrap();
        println!("{}", output);
 
        let res = std::process::Command::new("curl")
            .arg("--cacert")
            .arg("cert.pem")
            .arg("-X")
            .arg("POST")
            .arg("https://localhost:8080/graphql")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(r#"{"query":"{ zeekdata { sourceIp } }"}"#)
            .output()
            .expect("failed to execute process");
        let output = std::str::from_utf8(&res.stdout).unwrap();
        println!("{}", output);
 
        let res = std::process::Command::new("curl")
            .arg("--cacert")
            .arg("cert.pem")
            .arg("-X")
            .arg("POST")
            .arg("https://localhost:8080/graphql")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(r#"{"query":"{ zeekdata }"}"#)
            .output()
            .expect("failed to execute process");
        let output = std::str::from_utf8(&res.stdout).unwrap();
        println!("{}", output);
    }

    #[test]
    fn test_hello() 
    {
        let res = std::process::Command::new("curl")
            .arg("--cacert")
            .arg("cert.pem")
            .arg("https://localhost:8080/hello")
            .output()
            .expect("failed to execute process");
        let output = std::str::from_utf8(&res.stdout).unwrap();
        println!("{}", output);
    }
 
    #[test]
    fn test_read_header()
    {
        use crate::LogHeader;
        // these values represent the input from the user.
        let date_dir = "zeek-test-logs/2024-07-02";
        let log_type = "conn";
        let start_time = "00:00:00";
        let end_time = "01:00:00";
        let log_gz = "log.gz";
        let header = format!("{}/{}.{}-{}.{}",date_dir, log_type, start_time, end_time, log_gz);
        let date_dir = std::path::Path::new(&header);
        let header = LogHeader::set_header(&date_dir);
        assert!(header.separator.is_whitespace());
        assert!(header.set_separator.len() > 0);
        assert!(header.empty_field.len() > 0);
        assert!(header.unset_field.len() > 0);
        assert!(header.path.len() > 0);
        assert!(header.open.len() > 0);
        assert!(header.fields.len() > 0);
        assert!(header.types.len() > 0);
        println!("{header:?}");
    }
    #[test]
    fn test_log_data()
    {
        use crate::LogData;
        use crate::LogHeader;
        let date_dir = "zeek-test-logs/2024-07-02";
        let log_type = "dns";
        let start_time = "00:00:00";
        let end_time = "01:00:00";
        let log_gz = "log.gz";
        let header = format!("{}/{}.{}-{}.{}",date_dir, log_type, start_time, end_time, log_gz);
        let date_dir = std::path::Path::new(&header);
        let h = LogHeader::set_header(&date_dir); 
        let mut log : LogData = LogData::new(&h);
        log.add_field_entry("test123","one");
        log.add_field_entry("test123","two");
        log.add_field_entry("test123","three");
        log.add_field_entry("test1","one");
        assert_eq!(log.data.get("test123").unwrap(), &vec!["one","two","three"]);
        println!("passed: {:?}",log.data.get("test123").unwrap());
        assert_eq!(log.data.get("test1").unwrap(), &vec!["one"]);
        println!("passed: {:?}",log.data.get("test1").unwrap());
    }

    #[test]
    fn test_lifetime()
    {
        use crate::increment;
        use crate::print_val;
        let mut x = 10; 
        print_val(&x);
        increment(&mut x);
        print_val(&x);
    }
}













