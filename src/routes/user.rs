use crate::model::user::User;
use crate::util::error::Error;
use crate::util::fields;
use mongodb::bson::doc;
use mongodb::Database;
use rocket::form::{Form, FromForm};
use rocket::http::{Cookie, CookieJar};
use rocket::State;
use rocket::post;

#[derive(FromForm)]
pub struct CreateUserForm {
    pub name: String,
    pub password: String,
}

impl CreateUserForm {
    pub fn validate(&self) -> Result<(), Error> {
        fields::name::validate("Name", &self.name)?;
        fields::password::validate(&self.password)?;
        Ok(())
    }
}

#[get("/load")]
pub async fn load<'a>(user: Result<User, Error>) -> Result<String, Error> {
    let user = user?;
    Ok(user.name)
}

#[post("/create", format = "form", data = "<form>")]
pub async fn create<'a>(db: &State<Database>, form: Form<CreateUserForm>) -> Result<String, Error> {
    form.validate()?;
    let user = User::new(&form)?;
    db.collection::<User>("user")
        .insert_one(&user, None)
        .await?;
    let message = format!("User {} created.", &user.name);
    Ok(message)
}

#[derive(FromForm)]
pub struct SignInForm {
    pub name: String,
    pub password: String,
}

impl SignInForm {
    pub fn validate(&self) -> Result<(), Error> {
        fields::name::validate("Name", &self.name)?;
        fields::password::validate(&self.password)?;
        Ok(())
    }
}

#[post("/sign-in", format = "form", data = "<form>")]
pub async fn sign_in<'a>(
    db: &State<Database>,
    form: Form<SignInForm>,
    jar: &'a CookieJar<'a>,
) -> Result<String, Error> {
    form.validate()?;
    let filter = doc! {"name" : &form.name};
    let user = db
        .collection::<User>("user")
        .find_one(filter, None)
        .await?
        .ok_or(Error::NotFound(format!("User {} not found", &form.name)))?;
    let id = user
        .id
        .ok_or(Error::Server("User has no id".to_string()))?
        .to_string();
    if fields::password::verify(&user.password, &form.password)? {
        jar.add_private(Cookie::new("id", id));
        Ok(user.name)
    } else {
        return Err(Error::Unauthorized("Incorrect password".to_string()));
    }
}

#[get("/sign_out")]
pub async fn sign_out<'a>(jar: &CookieJar<'a>) -> &'a str {
    jar.remove_private(Cookie::named("id"));
    "signed out"
}

// use rocket::response::stream::{Event, EventStream};
// use rocket::tokio::sync::broadcast::{error::RecvError, Sender};
// use rocket::tokio::time::{interval, Duration};
// use rocket::tokio::{pin, select};

// struct UserDisconnect {
//     user_name: String,
// }

// impl Drop for UserDisconnect {
//     fn drop(&mut self) {
//         println!("{} disconnected", self.user_name);
//     }
// }

// #[get("/doctor2")]
// pub async fn doctor2(
//     user: Result<User, Error>,
//     mut shutdown: Shutdown,
// ) -> Result<EventStream![], Error> {
//     let user = user.or(Err(Error::NoContent("Not signed in".to_string())))?;

//     let stream = EventStream! {
//         let _gonna_drop = UserDisconnect { user_name: user.name };
//         let interval = interval(Duration::from_secs(1));
//         pin!(interval);
//         loop {
//             let _ = select! {
//                 _ = interval.tick() => {
//                     println!("tick");
//                     ()
//                 },
//                 _ = &mut shutdown => break,
//             };
//             yield Event::empty();
//         }
//     };

//     Ok(stream)
// }

// #[get("/doctor")]
// pub async fn doctor(
//     user: Result<User, Error>,
//     queue: &State<Sender<User>>,
//     mut shutdown: Shutdown,
// ) -> Result<EventStream![], Error> {
//     let user = user.or(Err(Error::NoContent("Not signed in".to_string())))?;
//     let mut rx = queue.subscribe();

//     let (send, recv) = rocket::tokio::sync::oneshot::channel::<()>();

//     let stream = EventStream! {
//         let _ = send;
//         let mut alive = true;
//         let interval = interval(Duration::from_secs(7));
//         pin!(interval);
//         loop {
//             let _ = select! {
//                 heartbeat = rx.recv() => match heartbeat {
//                     Ok(u) => {
//                         if u.id == user.id {
//                             println!("{} Was alive: {alive}", user.name);
//                             alive = true;
//                             interval.reset();
//                         } else {
//                             continue
//                         }
//                     },
//                     Err(RecvError::Closed) => {
//                         println!("closed");
//                         break
//                     },
//                     Err(RecvError::Lagged(_)) => continue,
//                 },
//                 _ = interval.tick() => {
//                     if alive {
//                         alive = false;
//                         continue
//                     } else {
//                         println!("{} DEAD!!", user.name);
//                         continue;
//                     }
//                 },
//                 _ = &mut shutdown => break,
//             };
//             yield Event::empty().with_retry(Duration::from_secs(5));
//         }
//         println!("outside");
//     };

//     rocket::tokio::spawn(async move {
//         // Wait while send is alive
//         let _ = recv.await;
//         println!("User disconnected");
//     });

//     Ok(stream)
// }

// #[get("/heartbeat")]
// pub async fn heartbeat(
//     user: Result<User, Error>,
//     queue: &State<Sender<User>>,
// ) -> Result<String, Error> {
//     let user = user?;
//     let _ = queue.send(user);
//     Ok("alive".to_string())
// }
