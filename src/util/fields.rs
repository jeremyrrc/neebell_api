use crate::util::error::Error;
use mongodb::bson::oid::ObjectId;
use sodiumoxide::crypto::pwhash::argon2id13::{self, pwhash, pwhash_verify, HashedPassword};

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref NAME_REGEX: Regex = Regex::new(r"[A-Za-z0-9\-]$").unwrap();
}

const MIN_NAME_LEN: usize = 1;
const MAX_NAME_LEN: usize = 25;

const MIN_PASS_LEN: usize = 8;
const MAX_PASS_LEN: usize = 50;

const MIN_MESS_LEN: usize = 1;
const MAX_MESS_LEN: usize = 200;

const MAX_PERMITTED_USERS: usize = 50;

fn validate_length(param_key: &str, value: &str, min: usize, max: usize) -> Result<(), Error> {
    if value.len() < min {
        return Err(Error::BadRequest(format!(
            "{param_key} must have at least {min} character(s)"
        )));
    }
    if value.len() > max {
        return Err(Error::BadRequest(format!(
            "{param_key} must have less than {max} characters"
        )));
    }
    Ok(())
}

pub mod oid_hex {
    use super::*;
    pub fn validate(hex: &str) -> Result<(), Error> {
        ObjectId::parse_str(hex)?;
        Ok(())
    }
}

pub mod name {
    use super::*;
    pub fn validate(param_key: &str, name: &str) -> Result<(), Error> {
        validate_length(param_key, name, MIN_NAME_LEN, MAX_NAME_LEN)?;
        if !NAME_REGEX.is_match(name) {
            return Err(Error::BadRequest(format!(
                "{param_key} is not a valid name."
            )));
        }
        Ok(())
    }
}

pub mod name_list {
    use super::*;
    pub fn validate(param_key: &str, list: &[String]) -> Result<(), Error> {
        if list.len() > MAX_PERMITTED_USERS {
            return Err(Error::BadRequest(format!(
                "{param_key} is too large. The max is {MAX_PERMITTED_USERS}"
            )));
        }
        for n in list {
            name::validate(n, n)?;
        }
        Ok(())
    }
}

pub mod password {
    use super::*;
    pub fn validate(passwd: &str) -> Result<(), Error> {
        validate_length("Password", passwd, MIN_PASS_LEN, MAX_PASS_LEN)
    }

    pub fn hash(passwd: &str) -> Result<HashedPassword, Error> {
        sodiumoxide::init().or(Err(Error::Server(
            "Could not intialize password hash".to_string(),
        )))?;
        let hash = pwhash(
            passwd.as_bytes(),
            argon2id13::OPSLIMIT_INTERACTIVE,
            argon2id13::MEMLIMIT_INTERACTIVE,
        )
        .or(Err(Error::Server("Could not hash password".to_string())))?;
        Ok(hash)
    }

    pub fn verify(pwh: &HashedPassword, passwd: &str) -> Result<bool, Error> {
        sodiumoxide::init().or(Err(Error::Server(
            "Could not intialize password verification".to_string(),
        )))?;
        Ok(pwhash_verify(pwh, passwd.as_bytes()))
    }
}

pub mod message {
    use super::*;

    pub fn validate(message: &str) -> Result<(), Error> {
        validate_length("Message", message, MIN_MESS_LEN, MAX_MESS_LEN)
    }
}
