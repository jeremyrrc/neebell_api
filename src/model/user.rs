use crate::model::forum::Forum;
use crate::routes::user::CreateUserForm;
use crate::util::error::Error;
use crate::util::fields::{name, password};
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::Database;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::{Deserialize, Serialize};
use rocket::State;
use sodiumoxide::crypto::pwhash::argon2id13::HashedPassword;

#[derive(Debug, Deserialize, Serialize)]
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

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = Error;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let db = if let Some(d) = request.guard::<&State<Database>>().await.succeeded() {
            d
        } else {
            return Outcome::Failure((
                Status::InternalServerError,
                Error::Server("Database not found".to_string()),
            ));
        };
        let oid = request
            .cookies()
            .get_private("id")
            .and_then(|cookie| ObjectId::parse_str(cookie.value()).ok());
        if let Some(o) = oid {
            let filter = doc! {"_id": o};
            let r = db.collection::<User>("user").find_one(filter, None).await;
            match r {
                Ok(opt) => match opt {
                    None => Outcome::Failure((
                        Status::Unauthorized,
                        Error::Unauthorized("User not found.".to_string()),
                    )),
                    Some(user) => Outcome::Success(user),
                },
                Err(_e) => Outcome::Failure((
                    Status::InternalServerError,
                    Error::Server("Database error.".to_string()),
                )),
            }
        } else {
            return Outcome::Failure((
                Status::Unauthorized,
                Error::Unauthorized("Not signed in.".to_string()),
            ));
        }
    }
}
