// now learn how this all works
use async_graphql::{Schema, Context, Object, Result, EmptyMutation, EmptySubscription};
use async_graphql_actix_web::{GraphQLRequest, GraphQLResponse};
use actix_web::{web, App, HttpServer, Responder};
use std::fs::File;
use std::io::{self, Read};
use flate2::read::GzDecoder;
use std::io::Write;

struct Query;

#[Object]
impl Query {
    async fn zeek_logs(&self, _ctx: &Context<'_>) -> Result<String> {
        let path = "zeek-test-logs/2024-07-03/ssh.02:00:00-03:00:00.log.gz";
        let output = std::process::Command::new("zcat")
            .arg(path)
            .output()
            .expect("failed to execute process");
        let output = std::str::from_utf8(&output.stdout).unwrap();
        Ok(output.to_string())
    }
    async fn add(&self, a: i32, b: i32) -> i32 
    {
        a + b
    }
    async fn hello(&self) -> String {
        "world".to_string()
    }
}

type AppSchema = Schema<Query, EmptyMutation, EmptySubscription>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Build the GraphQL schema
    let schema = Schema::build(Query, EmptyMutation, EmptySubscription).finish();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(schema.clone()))
            .service(web::resource("/graphql").route(web::post().to(graphql_handler)))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

async fn hello_handler(schema: web::Data<AppSchema>, req: GraphQLRequest) -> GraphQLResponse {
    schema.execute("{ hello }").await.into()
}


async fn graphql_handler(schema: web::Data<AppSchema>, req: GraphQLRequest) -> GraphQLResponse {
    // Execute the GraphQL request and return the response
    schema.execute(req.into_inner()).await.into()
    //schema.execute("{add(a: 10, b: 20 }").await.into()
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
}
