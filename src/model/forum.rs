use mongodb::bson::{doc, oid::ObjectId, Document};
use rocket::serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Forum {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub name: String,
    pub owner_id: ObjectId,
    pub permitted_users: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct ForumListItem {
    _id: ObjectId,
    name: String,
    permitted_users: Vec<String>,
}

impl ForumListItem {
    pub fn projection() -> Document {
        doc! {
            "_id" : 1,
            "name" : 1,
            "permitted_users": 1,
        }
    }
}
