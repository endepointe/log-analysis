// now learn how this all works
use async_graphql::{Schema, Context, Object, Result, EmptyMutation, EmptySubscription};
use async_graphql_actix_web::{GraphQLRequest, GraphQLResponse};
use actix_web::{web, App, HttpServer, Responder};
use std::fs::File;
use std::io::{self, Read};
use flate2::read::GzDecoder;

struct Query;

#[Object]
impl Query {
    async fn zeek_logs(&self, _ctx: &Context<'_>) -> Result<String> {
        // Define the path to the Zeek log file
        let path = "logs/2024-07-03/ssh.02:00:00-03:00:00.log.gz";
        // Read and decompress the file
        let file = File::open(path).map_err(|e| async_graphql::Error::new(e.to_string()))?;
        let mut gz = GzDecoder::new(file);
        let mut data = String::new();
        gz.read_to_string(&mut data).map_err(|e| async_graphql::Error::new(e.to_string()))?;
        // Return the file contents
        Ok(data)
    }
}

type AppSchema = Schema<Query, EmptyMutation, EmptySubscription>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Build the GraphQL schema
    let schema = Schema::build(Query, EmptyMutation, EmptySubscription).finish();

    // Configure and start the Actix-web server
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(schema.clone()))
            .service(web::resource("/graphql").route(web::post().to(graphql_handler)))
    })
    .bind("0.0.0.0:8080")? // Bind to the appropriate IP and port
    .run()
    .await
}

async fn graphql_handler(schema: web::Data<AppSchema>, req: GraphQLRequest) -> GraphQLResponse {
    // Execute the GraphQL request and return the response
    schema.execute(req.into_inner()).await.into()
}



/*
use actix_web::{get, web, App, HttpServer, Responder};

#[get("/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder 
{
    format!("Hello {}", name)
}


#[actix_web::main]
async fn
main() -> std::io::Result<()> 
{
    HttpServer::new(|| {
        App::new().service(greet)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
*/
