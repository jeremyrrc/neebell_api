use crate::model::user::User;
use crate::util::error::Error;
use crate::util::fields;
use mongodb::bson::doc;
use mongodb::Database;
use rocket::form::{Form, FromForm};
use rocket::http::{Cookie, CookieJar};
use rocket::post;
use rocket::State;

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
