use mongodb::{Client, Database};
use rocket::fairing::AdHoc;
use rocket::http::Header;
use rocket::routes;
use rocket::serde::Deserialize;
use rocket::tokio::sync::broadcast::channel;
use rocket::tokio::fs::read_to_string;
use std::error::Error;
use toml;
mod model;

mod routes;
mod util;

#[macro_use]
extern crate rocket;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Cors {
    pub allow_origin: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct DB {
    pub uri: String,
    pub name: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Config {
    pub cors: Cors,
    pub mongodb: DB,
}

#[rocket::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let s = read_to_string("../Config.toml").await.unwrap();
    let config: Config = toml::from_str(s.as_str()).unwrap();

    let cors = AdHoc::on_response("CORS", move |_, resp| {
        Box::pin(async move {
            resp.set_header(Header::new(
                "Access-Control-Allow-Origin",
                "http://127.0.0.1:5173",
            ));
            resp.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
            resp.set_header(Header::new(
                "Access-Control-Allow-Methods",
                "POST, GET, OPTIONS",
            ));
            resp.set_header(Header::new("Access-Control-Allow-Headers", "Content-Type"));
            resp.set_header(Header::new("Access-Control-Max-Age", "86400"));
        })
    });

    let client = Client::with_uri_str(&config.mongodb.uri).await.unwrap();
    let db: Database = client.database(&config.mongodb.name.as_str());
    let _ = rocket::build()
        .attach(cors)
        .manage(db)
        .manage(channel::<routes::forum::Message>(1024).0)
        .manage(channel::<routes::forum::AddedPermittedUsers>(1024).0)
        .manage(channel::<routes::forum::RemovedPermittedUsers>(1024).0)
        .manage(channel::<routes::forum::Listener>(1024).0)
        .register("/", util::error::catchers::BASIC.clone())
        .mount(
            "/user",
            routes![
                routes::user::load,
                routes::user::create,
                routes::user::sign_in,
                routes::user::sign_out,
            ],
        )
        .mount(
            "/forum",
            routes![
                routes::forum::listen_messages,
                routes::forum::listen_listening_users,
                routes::forum::listen_updated_permitted_users,
                routes::forum::message,
                routes::forum::create,
                routes::forum::list_owned,
                routes::forum::list_permitted,
                routes::forum::update_users,
                routes::forum::forum,
            ],
        )
        .launch()
        .await?;
    Ok(())
}
