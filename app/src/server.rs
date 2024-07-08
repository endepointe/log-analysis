// now learn how this all works
use async_graphql::{Schema, Context, Object, Result, EmptyMutation, EmptySubscription};
use async_graphql_actix_web::{GraphQLRequest, GraphQLResponse};
use actix_web::{web, App, HttpServer, Responder};
use std::fs::File;
use std::io::{self, Read};
use flate2::read::GzDecoder;
use std::io::Write;
use std::sync::Mutex;

struct Query;
struct AppState {
    visits: Mutex<i32>,
}

#[Object]
impl Query {
    async fn zeek_logs(&self, _ctx: &Context<'_>, src_ip: String) -> Result<String> {
        println!("ctx: {:?}", _ctx.data::<String>());
        let path = "zeek-test-logs/2024-07-03/ssh.02:00:00-03:00:00.log.gz";
        let output = std::process::Command::new("zcat")
            .arg(path)
            .output()
            .expect("failed to execute process");
        let output = std::str::from_utf8(&output.stdout).unwrap();
        Ok(output.to_string())
    }
}

type AppSchema = Schema<Query, EmptyMutation, EmptySubscription>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let visits = web::Data::new(AppState { visits: 1000.into() });
    // Build the GraphQL schema
    let schema = Schema::build(Query, EmptyMutation, EmptySubscription)
        .data("data_hello".to_string())
        .finish();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(schema.clone()))
            .app_data(visits.clone())
            .service(web::resource("/hello").route(web::get().to(hello_handler)))
            .service(web::resource("/graphql").route(web::post().to(graphql_handler)))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

async fn hello_handler(schema: web::Data<AppState>) -> impl Responder {
    println!("ctx: {:?}", schema.visits);
    let mut visits = schema.visits.lock().unwrap();
    *visits += 1;
    format!("Hello, world! Visits: {}", visits)
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
            .arg("-X")
            .arg("POST")
            .arg("http://localhost:8080/graphql")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(r#"{"query":"{ zeekLogs }"}"#)
            .output()
            .expect("failed to execute process");
        let output = std::str::from_utf8(&res.stdout).unwrap();
        println!("{}", output);
    }
    #[test]
    fn test_hello() 
    {
        let res = std::process::Command::new("curl")
            .arg("-X")
            .arg("GET")
            .arg("http://localhost:8080/hello")
            .output()
            .expect("failed to execute process");
        let output = std::str::from_utf8(&res.stdout).unwrap();
        println!("{}", output);
    }
}
