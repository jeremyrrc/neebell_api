use mongodb::{Client, Database};
use rocket::serde::Deserialize;
use rocket::tokio::sync::broadcast::channel;
use toml;
mod model;

mod routes;
mod util;

#[macro_use]
extern crate rocket;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct DB {
    pub uri: String,
    pub name: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Config {
    pub mongodb: DB,
}

#[launch]
async fn rocket() -> _ {
    let string_config = std::fs::read_to_string("../Config.toml").unwrap();
    let config: Config = toml::from_str(string_config.as_str()).unwrap();
    let client = Client::with_uri_str(config.mongodb.uri).await.unwrap();
    let db: Database = client.database(config.mongodb.name.as_str());
    rocket::build()
        .manage(db)
        .manage(channel::<routes::forum::Message>(1024).0)
        .register("/", util::error::catchers::BASIC.clone())
        .mount(
            "/user",
            routes![routes::user::create, routes::user::sign_in,],
        )
        .mount(
            "/forum",
            routes![
                routes::forum::listen,
                routes::forum::message,
                routes::forum::create,
                routes::forum::list_owned,
                routes::forum::list_permitted,
                routes::forum::update_users,
            ],
        )
}
