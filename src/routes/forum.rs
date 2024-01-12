use futures::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::options::{FindOneOptions, FindOptions};
use mongodb::Database;
use rocket::form::{Form, FromForm};
use rocket::serde::json::Json;
use rocket::serde::Serialize;
use rocket::State;
use rocket::{post, Request};
use std::collections::HashSet;

use crate::model::forum::{Forum, ForumItem, ForumListItem};
use crate::model::user::{user_by_token, User};
use crate::util::error::Error;
use crate::util::fields;
use crate::{allow_origin, Secret};

use rocket::response::stream::{Event, EventStream};
use rocket::tokio::sync::broadcast::{error::RecvError, Sender};
use rocket::tokio::time::{interval, Duration};
use rocket::tokio::{pin, select};
use rocket::Shutdown;

#[derive(Serialize, Debug)]
#[serde(crate = "rocket::serde")]
enum MessageYield {
    Message(Message),
    Closed,
}

#[get("/listen-messages?<f>&<jwt>")]
pub async fn listen_messages<'a>(
    db: &'a State<Database>,
    secret: &'a State<Secret>,
    // user: Result<User, Error>,
    message_queue: &'a State<Sender<Message>>,
    unsubscribe_queue: &'a State<Sender<Unsubscribe>>,
    listeners_queue: &'a State<Sender<Listener>>,
    removed_queue: &'a State<Sender<RemovedPermittedUsers>>,
    f: String,
    jwt: String,
    mut shutdown: Shutdown,
) -> Result<EventStream![Event + 'a], Error> {
    println!("{jwt}");
    // let user = user.or(Err(Error::NoContent("Not signed in".to_string())))?;
    // user._permitted(&db, &f)
    //     .await
    //     .or(Err(Error::NoContent("Not signed in".to_string())))?;
    let user = user_by_token(&jwt, secret, db).await?;

    let listener = Listener {
        forum_hex_id: f,
        user_name: user.name,
    };

    let mut rx_message = message_queue.subscribe();
    let mut rx_unsubscribe = unsubscribe_queue.subscribe();
    let mut rx_removed = removed_queue.subscribe();

    let (signal, mut close) = rocket::tokio::sync::mpsc::channel::<()>(32);

    let stream = EventStream! {
        let interval = interval(Duration::from_secs(3));
        pin!(interval);

        loop {
            let msg = select! {
                msg = rx_message.recv() => match msg {
                    Ok(msg) => {
                        if msg.forum_hex_id == listener.forum_hex_id {
                            MessageYield::Message(msg)
                        } else {
                            continue
                        }
                    },
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                un = rx_unsubscribe.recv() => match un {
                    Ok(un) => {
                        if un.forum_hex_id == listener.forum_hex_id && un.user_name == listener.user_name {
                            // MessageYield::Closed
                            break
                        } else {
                            continue
                        }
                    },
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                rm = rx_removed.recv() => match rm {
                    Ok(rm) => {
                        if rm.forum_hex_id == listener.forum_hex_id && rm.removed.contains(&listener.user_name) {
                            // MessageYield::Closed
                            break
                        } else {
                            continue
                        }
                    },
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                _ = interval.tick() => {
                    let _ = listeners_queue.send(listener.clone());
                    continue
                },
                _ = close.recv() => break,
                _ = &mut shutdown => break,
            };

            match msg {
                MessageYield::Message(m) => yield Event::json(&m),
                MessageYield::Closed => {
                    let _ = signal.clone().send(());
                    close.close();
                    yield Event::empty().event("closed".to_string())
                }
            }
        }
    };

    Ok(stream)
}

#[derive(Clone, Serialize, Debug)]
#[serde(crate = "rocket::serde")]
pub struct Listener {
    pub forum_hex_id: String,
    pub user_name: String,
}

#[get("/listen-listening-users?<f>&<jwt>")]
pub async fn listen_listening_users(
    db: &State<Database>,
    // user: Result<User, Error>,
    queue: &State<Sender<Listener>>,
    f: String,
    jwt: String,
    secret: &State<Secret>,
    mut end: Shutdown,
) -> Result<EventStream![], Error> {
    // let user = user.or(Err(Error::NoContent("Not signed in".to_string())))?;
    let user = user_by_token(&jwt, secret, db).await?;
    user._permitted(&db, &f)
        .await
        .or(Err(Error::NoContent("Not signed in".to_string())))?;
    let mut rx = queue.subscribe();
    Ok(EventStream! {
        loop {
            let user_name = select! {
                lis = rx.recv() => match lis {
                    Ok(lis) => {
                        if lis.forum_hex_id == f && lis.user_name != user.name{
                            lis.user_name
                        } else {
                            continue
                        }
                    },
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                _ = &mut end => break,
            };
            yield Event::data(user_name.clone());
        }
    })
}

#[derive(Clone, Serialize, FromForm, Debug)]
#[serde(crate = "rocket::serde")]
pub struct Message {
    pub forum_hex_id: String,
    pub user: String,
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
    let message = message.into_inner();
    let _r = queue.send(message);
    Ok("Message sent".to_string())
}

#[derive(Clone, Serialize, Debug)]
#[serde(crate = "rocket::serde")]
pub struct Unsubscribe {
    pub forum_hex_id: String,
    pub user_name: String,
}

#[get("/unsubscribe-messages?<f>")]
pub async fn unsubscribe_messages(
    user: Result<User, Error>,
    queue: &State<Sender<Unsubscribe>>,
    f: String,
) -> Result<(), Error> {
    let user = user?;
    let _ = queue.send(Unsubscribe {
        forum_hex_id: f,
        user_name: user.name,
    });
    Ok(())
}

#[derive(Clone, Serialize, Debug)]
#[serde(crate = "rocket::serde")]
pub struct AddedPermittedUsers {
    pub forum_hex_id: String,
    pub added: Vec<String>,
}

#[derive(Clone, Serialize, Debug)]
#[serde(crate = "rocket::serde")]
pub struct RemovedPermittedUsers {
    pub forum_hex_id: String,
    pub removed: Vec<String>,
}

#[derive(Serialize, Debug)]
#[serde(crate = "rocket::serde")]
enum UpdatePermittedUsersMessage {
    Add(AddedPermittedUsers),
    Remove(RemovedPermittedUsers),
}

#[get("/listen-updated-permitted-users?<f>&<jwt>")]
pub async fn listen_updated_permitted_users(
    db: &State<Database>,
    // user: Result<User, Error>,
    added_queue: &State<Sender<AddedPermittedUsers>>,
    removed_queue: &State<Sender<RemovedPermittedUsers>>,
    f: String,
    jwt: String,
    secret: &State<Secret>,
    mut shutdown: Shutdown,
) -> Result<EventStream![], Error> {
    // let user = user.or(Err(Error::NoContent("Not signed in".to_string())))?;
    let user = user_by_token(&jwt, secret, db).await?;
    user._permitted(&db, &f)
        .await
        .or(Err(Error::NoContent("Not signed in".to_string())))?;
    let mut rx_added = added_queue.subscribe();
    let mut rx_removed = removed_queue.subscribe();
    Ok(EventStream! {
        loop {
            let msg = select! {
                msg = rx_added.recv() => match msg {
                    Ok(msg) => {
                        if msg.forum_hex_id == f {
                            UpdatePermittedUsersMessage::Add(msg)
                        } else {
                            continue
                        }
                    },
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                msg = rx_removed.recv() => match msg {
                    Ok(msg) => {
                        if msg.forum_hex_id == f {
                            UpdatePermittedUsersMessage::Remove(msg)
                        } else {
                            continue
                        }
                    },
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                _ = &mut shutdown => break,
            };
            // match msg {
            //     UpdatePermittedUsersMessage::Add(m) => yield Event::json(&m.added).event("added".to_string()),
            //     UpdatePermittedUsersMessage::Remove(m) => yield Event::json(&m.removed).event("removed".to_string())
            // }
            yield Event::json(&msg)
            // match msg {
            //     UpdatePermittedUsersMessage::Add(m) => yield Event::json(&m.added).event("added".to_string()),
            //     UpdatePermittedUsersMessage::Remove(m) => yield Event::json(&m.removed).event("removed".to_string())
            // }
        }
    })
}

#[derive(Clone, FromForm, Serialize, Debug)]
#[serde(crate = "rocket::serde")]
pub struct UpdatePermittedUsers {
    pub forum_hex_id: String,
    pub permitted_users: String,
}

impl UpdatePermittedUsers {
    pub fn process(&self) -> Result<Vec<String>, Error> {
        fields::oid_hex::validate(&self.forum_hex_id)?;
        let changed: Vec<String> = self
            .permitted_users
            .split(",")
            .map(|v| v.trim().to_owned())
            .collect();
        fields::name_list::validate("Users", &changed)?;
        Ok(changed)
    }
}

#[post("/update-users", format = "form", data = "<update_users>")]
pub async fn update_users(
    db: &State<Database>,
    user: Result<User, Error>,
    added_queue: &State<Sender<AddedPermittedUsers>>,
    removed_queue: &State<Sender<RemovedPermittedUsers>>,
    update_users: Form<UpdatePermittedUsers>,
) -> Result<String, Error> {
    let changed = update_users.process()?;
    let user = user?;
    let forum_coll = db.collection::<Forum>("forum");
    let forum_id = ObjectId::parse_str(&update_users.forum_hex_id)?;
    let filter = doc! {"_id" : forum_id};
    let forum = forum_coll
        .find_one(filter.to_owned(), None)
        .await?
        .ok_or(Error::NotFound("Forum not found.".to_string()))?;
    if user.id != Some(forum.owner_id) {
        return Err(Error::Unauthorized(format!(
            "User {} is not the owner of this forum and cannot update the permitted users.",
            &user.name
        )));
    }
    let current = forum.permitted_users;
    if changed == current {
        return Ok("No change".to_string());
    }
    let set = doc! {
        "$set": {
            "permitted_users" : &changed
        }
    };

    let current: HashSet<String> = current.iter().cloned().collect();
    let changed: HashSet<String> = changed.iter().cloned().collect();

    let removed: Vec<String> = (&current - &changed).iter().cloned().collect();
    if removed.contains(&forum.owner) {
        return Err(Error::BadRequest(format!(
            "Cannot remove the owner of the forum: {}",
            &forum.owner
        )));
    }
    let added: Vec<String> = (&changed - &current).iter().cloned().collect();

    let _ = forum_coll.update_one(filter, set, None).await?;

    if !removed.is_empty() {
        let _ = removed_queue.send(RemovedPermittedUsers {
            forum_hex_id: update_users.forum_hex_id.clone(),
            removed,
        });
    }

    if !added.is_empty() {
        let _ = added_queue.send(AddedPermittedUsers {
            forum_hex_id: update_users.forum_hex_id.clone(),
            added,
        });
    }

    Ok("Updated".to_string())
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
        owner: user.name.clone(),
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

#[get("/forum?<f>")]
pub async fn forum(
    db: &State<Database>,
    user: Result<User, Error>,
    f: String,
) -> Result<Json<ForumItem>, Error> {
    let user = user?;
    let opts = FindOneOptions::builder()
        .projection(ForumItem::projection())
        .build();
    let id = ObjectId::parse_str(f)?;
    let filter = doc! {"_id": &id, "permitted_users": &user.name };
    let forum = db
        .collection::<ForumItem>("forum")
        .find_one(filter, Some(opts))
        .await?
        .ok_or(Error::NotFound(
            "The forum may be deleted, or you are not a permitted user.".to_string(),
        ))?;
    Ok(Json(forum))
}
