use futures::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::options::FindOptions;
use mongodb::Database;
use rocket::form::{Form, FromForm};
use rocket::post;
use rocket::serde::Serialize;
use rocket::serde::{json::Json, Deserialize};
use rocket::State;

use crate::model::forum::{Forum, ForumListItem};
use crate::model::user::User;
use crate::util::error::Error;
use crate::util::fields;

use rocket::response::stream::{Event, EventStream};
use rocket::tokio::select;
use rocket::tokio::sync::broadcast::{error::RecvError, Sender};
use rocket::Shutdown;

#[get("/listen?<f>")]
pub async fn listen(
    db: &State<Database>,
    user: Result<User, Error>,
    queue: &State<Sender<Message>>,
    f: String,
    mut end: Shutdown,
) -> Result<EventStream![], Error> {
    let user = user?;
    user._permitted(&db, &f).await?;
    let mut rx = queue.subscribe();
    Ok(EventStream! {
        loop {
            let msg = select! {
                msg = rx.recv() => match msg {
                    Ok(msg) => {
                        if msg.forum_hex_id == f {
                            msg
                        } else {
                            continue
                        }
                    },
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                _ = &mut end => break,
            };
            yield Event::json(&msg);
        }
    })
}

#[derive(Clone, Serialize, FromForm, Debug)]
#[serde(crate = "rocket::serde")]
pub struct Message {
    pub user: String,
    pub forum_hex_id: String,
    pub value: String,
}

impl Message {
    pub fn validate(&self) -> Result<(), Error> {
        fields::oid_hex::validate(&self.forum_hex_id)?;
        fields::message::validate(&self.value)?;
        Ok(())
    }
}

#[post("/message", format = "form", data = "<message>")]
pub async fn message(
    db: &State<Database>,
    user: Result<User, Error>,
    queue: &State<Sender<Message>>,
    message: Form<Message>,
) -> Result<String, Error> {
    message.validate()?;
    let user = user?;
    user._permitted(&db, &message.forum_hex_id).await?;
    let _r = queue.send(message.into_inner());
    Ok("Message sent".to_string())
}

#[derive(FromForm)]
pub struct CreateForumForm {
    pub name: String,
}

impl CreateForumForm {
    pub fn validate(&self) -> Result<(), Error> {
        fields::name::validate("Forum name", &self.name)?;
        Ok(())
    }
}

#[post("/create", format = "form", data = "<form>")]
pub async fn create(
    db: &State<Database>,
    user: Result<User, Error>,
    form: Form<CreateForumForm>,
) -> Result<String, Error> {
    form.validate()?;
    let user = user?;
    let forum = Forum {
        id: None,
        owner_id: user.id.unwrap(),
        name: form.name.trim().to_string(),
        permitted_users: vec![user.name],
    };
    db.collection::<Forum>("forum")
        .insert_one(forum, None)
        .await?;
    Ok(format!("Forum '{}' created.", form.name))
}

#[get("/list-owned")]
pub async fn list_owned(
    db: &State<Database>,
    user: Result<User, Error>,
) -> Result<Json<Vec<ForumListItem>>, Error> {
    let user = user?;
    let opts = FindOptions::builder()
        .projection(ForumListItem::projection())
        .build();
    let filter = doc! {"owner_id": &user.id};
    let forums = db
        .collection::<ForumListItem>("forum")
        .find(filter, Some(opts))
        .await?
        .try_collect()
        .await?;
    Ok(Json(forums))
}

#[get("/list-permitted")]
pub async fn list_permitted(
    db: &State<Database>,
    user: Result<User, Error>,
) -> Result<Json<Vec<ForumListItem>>, Error> {
    let user = user?;
    let opts = FindOptions::builder()
        .projection(ForumListItem::projection())
        .build();
    let filter = doc! {"permitted_users": &user.name};
    let forums = db
        .collection::<ForumListItem>("forum")
        .find(filter, Some(opts))
        .await?
        .try_collect()
        .await?;
    Ok(Json(forums))
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UpdateUsers {
    pub id: String,
    pub permitted_users: Vec<String>,
}

impl UpdateUsers {
    pub fn validate(&self) -> Result<(), Error> {
        fields::oid_hex::validate(&self.id)?;
        fields::name_list::validate("Users", &self.permitted_users)?;
        Ok(())
    }
}

#[post("/update-users", format = "json", data = "<update_users>")]
pub async fn update_users(
    db: &State<Database>,
    user: Result<User, Error>,
    mut update_users: Json<UpdateUsers>,
) -> Result<String, Error> {
    update_users.validate()?;
    let user = user?;
    let forum_coll = db.collection::<Forum>("forum");
    let forum_id = ObjectId::parse_str(&update_users.id)?;
    let filter = doc! {"_id" : forum_id};
    let forum = forum_coll
        .find_one(filter.to_owned(), None)
        .await?
        .ok_or(Error::NotFound("Forum not found.".to_string()))?;
    if user.id != Some(forum.owner_id) {
        return Err(Error::Unauthorized(format!(
            "User {} is not the owner of this forum.",
            &user.name
        )));
    }
    update_users.permitted_users.insert(0, user.name);
    let set = doc! {
        "$set": {
            "permitted_users" : update_users.permitted_users.to_owned()
        }
    };
    let _result = forum_coll.update_one(filter, set, None).await?;

    Ok("Permitted users updated".to_string())
}
