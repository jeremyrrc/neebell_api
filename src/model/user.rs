use crate::model::forum::Forum;
use crate::routes::user::CreateUserForm;
use crate::util::error::Error;
use crate::util::fields::{name, password};
use crate::Secret;
use jsonwebtoken::{decode, DecodingKey, Validation};
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::Database;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::{Deserialize, Serialize};
use rocket::State;
use sodiumoxide::crypto::pwhash::argon2id13::HashedPassword;
use std::clone::Clone;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub name: String,
    pub password: HashedPassword,
}

impl User {
    pub fn new(form: &CreateUserForm) -> Result<Self, Error> {
        name::validate("Name", &form.name)?;
        password::validate(&form.password)?;
        let pass_hash = password::hash(&form.password)?;
        let user = User {
            id: None,
            name: form.name.trim().to_string(),
            password: pass_hash,
        };
        Ok(user)
    }

    // check if the user is a permitted user on a forum.
    pub async fn _permitted(&self, db: &Database, forum_hex_id: &str) -> Result<(), Error> {
        let forum_oid = ObjectId::parse_str(forum_hex_id)?;
        let filter = doc! {"_id": forum_oid, "permitted_users": &self.name};
        let _forum = db
            .collection::<Forum>("forum")
            .find_one(filter, None)
            .await?
            .ok_or(Error::Unauthorized(
                "The forum may be deleted, or you are not a permitted user.".to_string(),
            ))?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct UserByURLToken {
    user: User,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct JWTUserPayload {
    pub sub: String,
    pub oid: String,
    pub exp: usize,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = Error;
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header_value = match req.headers().get_one("Authorization") {
            Some(h) => &h["Bearer ".len()..],
            None => {
                return Outcome::Failure((
                    Status::BadRequest,
                    Error::Server("No authorization header".to_string()),
                ));
            }
        };

        let secret = match req.guard::<&State<Secret>>().await.succeeded() {
            // Some(s) => s.0.clone(),
            Some(s) => s,
            None => {
                return Outcome::Failure((
                    Status::InternalServerError,
                    Error::Server("Server configuraton error: No secret".to_string()),
                ));
            }
        };

        let db = match req.guard::<&State<Database>>().await.succeeded() {
            Some(db) => db,
            None => {
                return Outcome::Failure((
                    Status::InternalServerError,
                    Error::Server("Database not found".to_string()),
                ));
            }
        };

        let r = user_by_token(auth_header_value, secret, db).await;
        let user = match r {
            Ok(user) => user,
            Err(e) => {
                return Outcome::Failure((Status::Unauthorized, e));
            }
        };

        crate::allow_origin(req);

        Outcome::Success(user)
    }
}

pub async fn user_by_token(token: &str, secret: &Secret, db: &Database) -> Result<User, Error> {
    let jwt = decode::<JWTUserPayload>(
        &token,
        &DecodingKey::from_secret(&secret.0),
        &Validation::default(),
    )
    .map_err(|_| Error::Unauthorized("Bad token".to_string()))?;

    let oid =
        ObjectId::parse_str(jwt.claims.oid).map_err(|_| Error::BadRequest("Bad id".to_string()))?;

    let filter = doc! {"_id": oid};
    let user = db
        .collection::<User>("user")
        .find_one(filter, None)
        .await?
        .ok_or(Error::NotFound("User not found".to_string()))?;

    Ok(user)
}
