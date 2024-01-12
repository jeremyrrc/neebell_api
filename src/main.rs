use model::user::User;
use mongodb::{Client, Database};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::uri::Origin;
use rocket::http::{Method, Status};
use rocket::routes;
use rocket::serde::Deserialize;
use rocket::tokio::fs;
use rocket::tokio::sync::broadcast::channel;
use rocket::{Data, Request, Response};
use std::collections::HashSet;
use std::error::Error;
mod model;

mod routes;
mod util;

#[macro_use]
extern crate rocket;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Cors {
    pub allow_origin: Vec<String>,
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
    pub secret: String,
}

pub struct Secret(Vec<u8>);

struct CorsFairing {
    allow_origin: HashSet<String>,
}

pub struct Allowed(Option<String>);

pub fn allow_origin(req: &Request) -> bool {
    match req.headers().get_one("Origin") {
        Some(o) => {
            req.local_cache(|| Allowed(Some(o.to_string())));
            true
        }
        None => false,
    }
}

#[rocket::async_trait]
impl Fairing for CorsFairing {
    fn info(&self) -> Info {
        Info {
            name: "CORS",
            kind: Kind::Response | Kind::Request,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _: &mut Data<'_>) {
        let path = req.uri().path();
        if path == "/user/sign-in" {
            allow_origin(req);
            return;
        }
        if req.method() == Method::Options {
            allow_origin(req);
            return;
        }
        // let allow = req.headers().get_one("Origin").and_then(|o| {
        //     self.allow_origin.get(o)
        // });
        // if let None = allow {
        //     req.set_uri(Origin::parse("/cors-to-no-where").unwrap())
        // } else {
        //     req.local_cache(|| Allowed(allow.cloned()));
        // }
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        // let allowed_origin = match &req.local_cache(|| Allowed(None)).0 {
        //     Some(a) => a,
        //     None => return,
        // };
        if res.status() == Status::NotFound && req.method() == Method::Options {
            res.set_status(Status::Ok);
        }
        res.set_raw_header("Access-Control-Allow-Origin", "*");
        // res.set_raw_header("Access-Control-Allow-Credentials", "true");
        res.set_raw_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        res.set_raw_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization",
        );
        res.set_raw_header("Access-Control-Max-Age", "86400");
        res.set_raw_header("Vary", "Origin");
    }
}
use rocket::response::stream::{Event, EventStream};
use rocket::tokio::time::{self, Duration};

#[get("/ping")]
fn ping(user: User) -> EventStream![] {
    EventStream! {
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            yield Event::data(user.name.clone());
            interval.tick().await;
        }
    }
}

#[rocket::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let s = fs::read_to_string("../server-config.json").await.unwrap();
    let config: Config = rocket::serde::json::from_str(s.as_str()).unwrap();

    let cors = CorsFairing {
        allow_origin: config.cors.allow_origin.iter().cloned().collect(),
    };

    let client = Client::with_uri_str(&config.mongodb.uri).await.unwrap();
    let db: Database = client.database(&config.mongodb.name.as_str());

    let secret = Secret(config.secret.into_bytes());

    let _ = rocket::build()
        .attach(cors)
        .manage(db)
        .manage(secret)
        .manage(channel::<routes::forum::Message>(1024).0)
        .manage(channel::<routes::forum::Unsubscribe>(1024).0)
        .manage(channel::<routes::forum::AddedPermittedUsers>(1024).0)
        .manage(channel::<routes::forum::RemovedPermittedUsers>(1024).0)
        .manage(channel::<routes::forum::Listener>(1024).0)
        .register("/", util::error::catchers::BASIC.clone())
        .mount("/events", routes![ping])
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
                routes::forum::unsubscribe_messages,
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
