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

#[derive(Debug)]
struct TsvFormat
{
    seperator: String,
    set_seperator: String,
    unset_field: String,
    path: String,
    open: String,
    fields: Vec<String>,
    types: Vec<String>,
}
impl TsvFormat
{
    fn new(p : &std::path::Path) -> Self 
    {
        for content in p.read_dir().expect("some sort of path reading issue")
        {
            println!("{:?}", content);
        }
        TsvFormat 
        {
            seperator: String::from("seperator"),
            set_seperator: String::from("set the seperator"),
            unset_field: String::from("unset field character"),
            path: String::from("name of the type of zeek log"),
            open: String::from("creation date"),
            fields: Vec::new(),
            types: Vec::new(),
        }
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

fn get_zeek_header(path: &str) -> std::io::Result<()>
{
    let path : &std::path::Path = std::path::Path::new(path);
    let contents = std::fs::read_dir(&path);
    if contents.is_err() 
    {
        println!("ERROR(get_zeek_header): check file path");
        std::process::exit(1); // temp
    }
    for content in contents?
    {
        let dir = content?;
        let _file = dir.file_name();
        let f = _file.to_str().expect("failed to convert to string").split(".").collect::<Vec<&str>>();
        let f = f[0];
        //println!("{}", f);
    }

    Ok(())
}

async fn graphql_handler(schema: web::Data<AppSchema>, req: GraphQLRequest) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
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
    fn test_get_zeek_header()
    {
        let _ = super::get_zeek_header("zeek-test-logs/2024-07-02/");
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
    fn test_tsv_format()
    {
        use crate::TsvFormat;
        let log_path = std::path::Path::new("zeek-test-logs/2024-07-02/");
        let s : TsvFormat = TsvFormat::new(&log_path); 
        println!("{:?}", s);
    }

}
