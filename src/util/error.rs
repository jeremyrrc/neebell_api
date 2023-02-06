use mongodb::bson::oid::Error as OidError;
use mongodb::error::Error as MongoError;
use std::convert::From;
use std::fmt::Debug;
use std::time::SystemTimeError;

#[derive(Debug, Responder)]
pub enum Error {
    #[response(status = 500, content_type = "text")]
    Server(String),
    #[response(status = 404, content_type = "text")]
    NotFound(String),
    #[response(status = 401, content_type = "text")]
    Unauthorized(String),
    #[response(status = 400, content_type = "text")]
    BadRequest(String),
    #[response(status = 204, content_type = "text")]
    NoContent(String),
}

impl From<MongoError> for Error {
    fn from(e: MongoError) -> Self {
        println!("{}", e);
        Self::Server("Database error.".to_string())
    }
}

impl From<OidError> for Error {
    fn from(_e: OidError) -> Self {
        Self::BadRequest("Invalid id".to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(_e: std::io::Error) -> Self {
        Self::Server("I0 error".to_string())
    }
}

impl From<SystemTimeError> for Error {
    fn from(_e: SystemTimeError) -> Self {
        Self::Server("System time error".to_string())
    }
}

pub mod catchers {
    use lazy_static::lazy_static;
    use rocket::Catcher;

    #[catch(500)]
    fn server() -> &'static str {
        "Server error"
    }

    #[catch(404)]
    fn not_found() -> &'static str {
        "Not found"
    }

    #[catch(401)]
    fn unauthorized() -> &'static str {
        "Unathorized"
    }

    #[catch(400)]
    fn bad_request() -> &'static str {
        "Bad request"
    }

    #[catch(default)]
    fn default_catcher() -> &'static str {
        "Error"
    }

    lazy_static! {
        pub static ref BASIC: Vec<Catcher> = catchers![
            server,
            not_found,
            unauthorized,
            bad_request,
            default_catcher
        ];
    }
}
