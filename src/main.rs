use std::{convert::TryInto, iter::Iterator};
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use argon2::{self, Config as Argon2Config};
use anyhow::Result;
use jsonwebtoken::{encode, decode, TokenData, DecodingKey, Validation, Header, EncodingKey, Algorithm::RS256};
use lazy_static::lazy_static;
use std::sync::Arc;
use tide::Request;
use http_types::headers::HeaderValue;
use tide::security::{CorsMiddleware, Origin};
use tide_acme::{AcmeConfig, TideRustlsExt};
use mailchecker::is_valid;
use zxcvbn::{zxcvbn, Score};
use chbs::{config::BasicConfig, prelude::*};
use totp_rs::{Algorithm, Secret, TOTP};
use regex::Regex;

lazy_static! {
    static ref DB : Arc<rocksdb::DB> = {

        let prefix_extractor = rocksdb::SliceTransform::create_fixed_prefix(3);

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.set_prefix_extractor(prefix_extractor);

        let configure = env_var_config();
        let db = rocksdb::DB::open(&opts, configure.db).unwrap();
        Arc::new(db)
    };
}

#[derive(Deserialize, Debug, Clone)]
pub struct EnvVarConfig {
  pub port: u16,
  pub jwt_expiry: i64,
  pub jwt_rsa_private: String,
  pub jwt_rsa_public: String,
  pub origin: String,
  pub db: String,
  pub secure: bool,
  pub certs: String,
  pub domain: String,
  pub auto_cert: bool,
  pub key_path: String,
  pub cert_path: String,
  pub password_checker: bool,
  pub totp_duration: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub email: Option<String>,
    pub username: String,
    pub password: String,
    pub tenant_name: String,
    pub data: Option<serde_json::Value>,
    pub scopes: Option<Vec<String>>,
    pub totp: String,
    pub two_factor: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserForm {
    pub username: String,
    pub password: String,
    pub tenant_name: String,
    pub email: Option<String>,
    pub data: Option<serde_json::Value>,
    pub scopes: Option<Vec<String>>,
    pub two_factor: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateUserForm {
    pub username: String,
    pub email: Option<String>,
    pub password: Option<String>,
    pub data: Option<serde_json::Value>,
    pub scopes: Option<Vec<String>>,
    pub two_factor: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateQRForm {
    pub issuer: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateTOTPForm {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PasswordResetForm {
    pub totp: String,
    pub password: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RevokeUserForm {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub exp: i64,          
    pub iat: i64,         
    pub iss: String,         
    pub sub: String,
    pub aud: Vec<String>,
    pub scopes: String,
}

fn replace(key: String, value: Vec<u8>) -> Result<()> {
    DB.put(key.clone(), value.clone())?;
    Ok(())
}

fn modify_user(update_user_form: UpdateUserForm) -> Result<Option<String>> {
    match get_user_by_username(update_user_form.clone().username)? {
        Some(mut user) => {
                        
            match update_user_form.email {
                Some(email) => {
                    if is_valid(&email) {
                        user.email = Some(email);
                    }
                },
                None => {}
            }
            
            user.data = update_user_form.data;
            user.scopes = update_user_form.scopes;
            user.two_factor = update_user_form.two_factor;

            match update_user_form.password {
                Some(password) => {

                    let configure = env_var_config();

                    if configure.password_checker {
                        let estimate = zxcvbn(&password, &[&user.username]);
                        if estimate.score() < Score::Three {
                            let err: String;
                            match estimate.feedback() {
                                Some(feedback) => {
                                    match feedback.warning() {
                                        Some(warning) => {
                                            err = format!("password is too weak because {}", warning);
                                        },
                                        None => {
                                            err = format!("password is too weak");
                                        }
                                    }
                                },
                                None => {
                                    err = format!("password is too weak");
                                }
                            }
                            let j = json!({"error": err}).to_string();
                            return Ok(Some(j));
                        }
                    }

                    let config = Argon2Config::default();
                    let uuid_string = Uuid::new_v4().to_string();
                    let salt =  uuid_string.as_bytes();
                    let password = password.as_bytes();
                    let hashed = argon2::hash_encoded(password, salt, &config).unwrap();
                    user.password = hashed;
                },
                None => {}
            }
            puts_user(user)?;
            Ok(None)
        },
        None => { Ok(None) }
    }
}

fn get_user_by_username(user_username: String) -> Result<Option<User>> {
    let users = get_users(&DB)?;
    Ok(users.into_iter().filter(|user| user.username == user_username).last())
}

fn get_users(db: &DB) -> Result<Vec<User>, rocksdb::Error> {
    let prefix = "users".to_string();
    let iter = db.prefix_iterator(prefix.as_bytes());
    let mut res: Vec<User> = Vec::new();

    for item in iter {
        match item {
            Ok((_, v)) => {
                let data: User = rmp_serde::from_slice(&v).unwrap();
                res.push(data);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(res)
}

fn puts_user(user: User) -> Result<()> {
    let key = format!("users_{}", user.username);
    let value = rmp_serde::to_vec_named(&user)?;
    replace(key, value)?;
    Ok(())
}

fn is_user_unique(user_username: String) -> Result<bool> {
    let users = get_users(&DB)?;
    for user in users {
        if user.username == user_username {
            return Ok(false);
        }
    }
    Ok(true)
}

fn jwt_scopes(scopes: Vec<String>) -> String {
    let scoped = scopes.join(" ");
    return scoped;
}

fn user_create(user_form: UserForm) -> Result<Option<String>> {

    match user_form.clone().email {
        Some(email) => {
            if !is_valid(&email) {
                let j = json!({"error": "email is invalid"}).to_string();
                return Ok(Some(j));
            }
        },
        None => {}
    }
    if !is_user_unique(user_form.clone().username)? {
        let j = json!({"error": "username already taken"}).to_string();
        return Ok(Some(j));
    } else {
        let configure = env_var_config();
        if configure.password_checker {
            let estimate = zxcvbn(&user_form.password, &[&user_form.username]);
            if estimate.score() < Score::Three {
                let err: String;
                match estimate.feedback() {
                    Some(feedback) => {
                        match feedback.warning() {
                            Some(warning) => {
                                err = format!("password is too weak because {}", warning);
                            },
                            None => {
                                err = format!("password is too weak");
                            }
                        }
                    },
                    None => {
                        err = format!("password is too weak");
                    }
                }
                let j = json!({"error": err}).to_string();
                return Ok(Some(j));
            }
        }

        let mut config = BasicConfig::default();
        config.words = 12;
        config.separator = "-".into();
        let scheme = config.to_scheme();
        let totp = scheme.generate();

        let mut scope_valid = true;
        match user_form.clone().scopes {
            Some(scopes) => {
                let re = Regex::new(r"^[^:]+:[^:]+$").unwrap();
                for scope in scopes {
                    if !re.is_match(&scope) {
                        scope_valid = false;
                    }
                }
            },
            None => {}
        }

        if !scope_valid {
            let j = json!({"error": "scopes are invalid"}).to_string();
            return Ok(Some(j));
        }

        let uuid = Uuid::new_v4();
        let config = Argon2Config::default();
        let uuid_string = Uuid::new_v4().to_string();
        let salt =  uuid_string.as_bytes();
        let password = user_form.password.as_bytes();
        let hashed = argon2::hash_encoded(password, salt, &config).unwrap();
        let new_user = User{
            id: uuid, 
            username: user_form.clone().username, 
            password: hashed, 
            tenant_name: user_form.clone().tenant_name,
            email: user_form.clone().email,
            data: user_form.clone().data,
            scopes: user_form.clone().scopes,
            totp,
            two_factor: user_form.clone().two_factor,
        };

        puts_user(new_user).unwrap();
        return Ok(None);
    }
}

async fn create_jwt(login: LoginForm) -> Result<Option<String>> {

    match get_user_by_username(login.username)? {
        Some(user) => {
            let verified = argon2::verify_encoded(&user.password, login.password.as_bytes())?;
            if verified {
                match user.two_factor {
                    Some(two_factor) => {
                        if two_factor {
                            match login.totp {
                                Some(token) => {
                                    let totp = TOTP::new(
                                        Algorithm::SHA512,
                                        6,
                                        1,
                                        30,
                                        Secret::Raw(user.clone().totp.as_bytes().to_vec()).to_bytes().unwrap(),
                                        Some(String::from("")),
                                        String::from(""),
                                    );
                                    let time = nippy::get_unix_ntp_time().await?;
                                    match totp {
                                        Ok(totp) => {
                                            if totp.check(&token, time.try_into()?) {
                                                let app = env_var_config();
                                                let iat = nippy::get_unix_ntp_time().await?;
                                                let exp = iat + app.jwt_expiry;
                                                let iss = "https://broker.upbase.dev/".to_string();
                                                let aud = ["https://broker.upbase.dev/userinfo".to_string()].to_vec();
                                                let scopes = jwt_scopes(user.scopes.clone().unwrap());
                                                let my_claims = Claims{sub: user.clone().username, exp, iat, scopes, iss, aud};
                                                let pem = async_std::fs::read(&app.jwt_rsa_private).await?;
                                                let token = encode(&Header::new(RS256), &my_claims, &EncodingKey::from_rsa_pem(&pem)?)?;
                                                return Ok(Some(token))
                                            } else {
                                               return Ok(None)
                                            }
                                        },
                                        Err(_) => { return Ok(None) }
                                    }
                                },
                                None => { Ok(None) }
                            }
                        } else {
                            let app = env_var_config();
                            let iat = nippy::get_unix_ntp_time().await?;
                            let exp = iat + app.jwt_expiry;
                            let iss = "https://broker.upbase.dev/".to_string();
                            let aud = ["https://broker.upbase.dev/userinfo".to_string()].to_vec();
                            let scopes = jwt_scopes(user.scopes.clone().unwrap());
                            let my_claims = Claims{sub: user.clone().username, exp, iat, iss, scopes, aud};
                            let pem = async_std::fs::read(&app.jwt_rsa_private).await?;
                            let token = encode(&Header::new(RS256), &my_claims, &EncodingKey::from_rsa_pem(&pem)?)?;
                            Ok(Some(token))                
                        }
                    },
                    None => {
                        let app = env_var_config();
                        let iat = nippy::get_unix_ntp_time().await.unwrap();
                        let exp = iat + app.jwt_expiry;
                        let iss = "https://broker.upbase.dev/".to_string();
                        let aud = ["https://broker.upbase.dev/userinfo".to_string()].to_vec();
                        let scopes = jwt_scopes(user.scopes.clone().unwrap());
                        let my_claims = Claims{sub: user.clone().username, exp, iat, iss, scopes, aud};
                        let pem = async_std::fs::read(&app.jwt_rsa_private).await.unwrap();
                        let token = encode(&Header::new(RS256), &my_claims, &EncodingKey::from_rsa_pem(&pem).unwrap()).unwrap();
                        Ok(Some(token))
                    }
                }
            } else {
                Ok(None)
            }
        },
        None => { Ok(None) }
    }
}

fn env_var_config() -> EnvVarConfig {
 
    let mut port : u16 = 8080;
    let mut jwt_expiry : i64 = 86400;
    let mut secure = false;
    let mut auto_cert = true;
    let mut origin = "*".to_string();
    let mut db: String = "db".to_string();
    let mut certs = "certs".to_string();
    let mut domain = "localhost".to_string();
    let mut key_path = "certs/private_key.pem".to_string();
    let mut cert_path = "certs/chain.pem".to_string();
    let mut password_checker = false;
    let mut totp_duration: u64 = 300;
    let mut jwt_rsa_private = "jwtRS256.key".to_string();
    let mut jwt_rsa_public = "jwtRS256.key.pub".to_string();
    let _ : Vec<String> = go_flag::parse(|flags| {
        flags.add_flag("port", &mut port);
        flags.add_flag("origin", &mut origin);
        flags.add_flag("jwt_expiry", &mut jwt_expiry);
        flags.add_flag("secure", &mut secure);
        flags.add_flag("db", &mut db);
        flags.add_flag("domain", &mut domain);
        flags.add_flag("certs", &mut certs);
        flags.add_flag("auto_cert", &mut auto_cert);
        flags.add_flag("key_path", &mut key_path);
        flags.add_flag("cert_path", &mut cert_path);
        flags.add_flag("password_checker", &mut password_checker);
        flags.add_flag("totp_duration", &mut totp_duration);
        flags.add_flag("jwt_rsa_private", &mut jwt_rsa_private);
        flags.add_flag("jwt_rsa_public", &mut jwt_rsa_public);
    });

    EnvVarConfig{port, origin, jwt_expiry, jwt_rsa_private, jwt_rsa_public, secure, domain, certs, db, auto_cert, key_path, cert_path, password_checker, totp_duration}
}

async fn create_user(mut req: Request<()>) -> tide::Result {
    let r =  req.body_string().await?;
    let user_form : UserForm = serde_json::from_str(&r)?;
    match user_create(user_form)? {
        Some(err) => {
            Ok(tide::Response::builder(400).body(err).header("content-type", "application/json").build())
        },
        None => {
            Ok(tide::Response::builder(200).body("").header("content-type", "application/json").build())
        }
    }
}

async fn jwt_verify(token: String) -> Result<Option<TokenData<Claims>>> {

    let mut parts = token.split(" ");
    let auth_type = parts.next().unwrap();
    if auth_type == "Bearer" {
        let token = parts.next().unwrap();
        let app = env_var_config();
        let pem = async_std::fs::read(&app.jwt_rsa_public).await?;
        let _ = match decode::<Claims>(&token,  &DecodingKey::from_rsa_pem(&pem)?,  &Validation::new(RS256)) {
            Ok(c) => { return Ok(Some(c)); },
            Err(_) => { return Ok(None); }
        };
    } else {
        return Ok(None)
    }
}

async fn verify_user(token: String) -> Result<Option<User>> {
    let jwt_value = jwt_verify(token).await?;
    match jwt_value {
        Some(jwt) => {
            let username = jwt.claims.sub;
            match get_user_by_username(username.clone())? {
                Some(user) => {
                    return Ok(Some(user))
                },
                None => {
                    return Ok(None)
                }
            }
        },
        None => { return Ok(None) }
    }
}

async fn login_user(mut req: Request<()>) -> tide::Result {
    let r = req.body_string().await?;
    let login_form: LoginForm = serde_json::from_str(&r)?;
    match create_jwt(login_form).await? {
        Some(jwt) => {
            let msg = json!({"jwt": jwt}).to_string();
            Ok(tide::Response::builder(200).body(msg).header("content-type", "application/json").build())
        },
        None => {
            Ok(tide::Response::builder(401).header("content-type", "application/json").build())
        }
    }
}


async fn health(_req: Request<()>) -> tide::Result {
    Ok(tide::Response::builder(200).body("OK").header("content-type", "text/plain").build())
}

async fn get_user(req: Request<()>) -> tide::Result {
    match req.header("authorization") {
        Some(bearer) => {
            let token = bearer.last().to_string();
            let check = verify_user(token).await?;
            match check {
                Some(user) => {
                    let j = json!({"user": user}).to_string();
                    Ok(tide::Response::builder(200).body(j).header("content-type", "application/json").build())
                },
                None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
            }
        },
        None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
    }
}

async fn update_user(mut req: Request<()>) -> tide::Result {
    let r = req.body_string().await?;
    let update_user_form: UpdateUserForm = serde_json::from_str(&r)?;
    match modify_user(update_user_form)? {
        Some(err) => {
            Ok(tide::Response::builder(400).body(err).header("content-type", "application/json").build())
        },
        None => {
            Ok(tide::Response::builder(200).body("").header("content-type", "application/json").build())
        }
    }
}

async fn create_qr(mut req: Request<()>) -> tide::Result {
    let r = req.body_string().await?;
    let create_qr_form: CreateQRForm = serde_json::from_str(&r)?;
    let totp = TOTP::new(
        Algorithm::SHA512,
        6,
        1,
        30,
        Secret::Raw(create_qr_form.username.clone().as_bytes().to_vec()).to_bytes().unwrap(),
        Some(String::from("")),
        String::from(""),
    )?;
    let qr_code = totp.get_url();
    Ok(tide::Response::builder(200).body(qr_code).header("content-type", "application/json").build())
}

async fn create_totp(mut req: Request<()>) -> tide::Result {
    let r = req.body_string().await?;
    let create_totp_form: CreateTOTPForm = serde_json::from_str(&r)?;
    match get_user_by_username(create_totp_form.username)? {
        Some(user) => {
            let totp = TOTP::new(
                Algorithm::SHA512,
                6,
                1,
                30,
                Secret::Raw(user.clone().totp.as_bytes().to_vec()).to_bytes().unwrap(),
                Some(String::from("")),
                String::from(""),
            )?;
            let qr_code = totp.get_url();
            Ok(tide::Response::builder(200).body(qr_code).header("content-type", "application/json").build())
        },
        None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
    }
}

async fn password_reset(mut req: Request<()>) -> tide::Result {
    let r = req.body_string().await?;
    let password_reset_form: PasswordResetForm = serde_json::from_str(&r)?;
    match get_user_by_username(password_reset_form.username)? {
        Some(mut user) => {
            let totp = TOTP::new(
                Algorithm::SHA512,
                6,
                1,
                30,
                Secret::Raw(user.clone().totp.as_bytes().to_vec()).to_bytes().unwrap(),
                Some(String::from("")),
                String::from(""),
            )?;
            let time = nippy::get_unix_ntp_time().await?;
            if totp.check(&password_reset_form.totp, time.try_into()?) {
                let config = Argon2Config::default();
                let uuid_string = Uuid::new_v4().to_string();
                let salt = uuid_string.as_bytes();
                let password = password_reset_form.password.as_bytes();
                let hashed = argon2::hash_encoded(password, salt, &config).unwrap();
                user.password = hashed;
                puts_user(user)?;
                Ok(tide::Response::builder(200).header("content-type", "application/json").build())
            } else {
                Ok(tide::Response::builder(401).header("content-type", "application/json").build())
            }
        },
        None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
    }
}

async fn insert_event(mut req: Request<()>) -> tide::Result {
    match req.header("authorization") {
        Some(bearer) => {
            let token = bearer.last().to_string();
            let check = verify_user(token).await?;
            match check {
                Some(user) => {
                    let r = req.body_string().await?;
                    let event: serde_json::Value = serde_json::from_str(&r)?;
                    let event_key = format!("events_{}", Uuid::new_v4());
                    let event_data = json!({
                        "user": user.username,
                        "tenant": user.tenant_name,
                        "event": event
                    });
                    let event_value = rmp_serde::to_vec_named(&event_data)?;
                    replace(event_key, event_value)?;
                    Ok(tide::Response::builder(200).header("content-type", "application/json").build())
                },
                None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
            }
        },
        None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
    }
}

async fn sse(req: Request<()>) -> tide::Result {
    match req.header("authorization") {
        Some(bearer) => {
            let token = bearer.last().to_string();
            let check = verify_user(token).await?;
            match check {
                Some(user) => {
                    let prefix = format!("events_{}", user.tenant_name);
                    let events: Vec<serde_json::Value> = DB.prefix_iterator(prefix.as_bytes())
                        .filter_map(|item| match item {
                            Ok((_, v)) => Some(rmp_serde::from_slice(&v).unwrap()),
                            Err(_) => None,
                        })
                        .collect();
                    let mut res = tide::Response::new(200);
                    res.insert_header("content-type", "text/event-stream");
                    res.insert_header("cache-control", "no-cache");
                    res.insert_header("connection", "keep-alive");
                    res.set_body(serde_json::to_string(&events)?);
                    Ok(res)
                },
                None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
            }
        },
        None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
    }
}

async fn revoke_user(mut req: Request<()>) -> tide::Result {
    let r = req.body_string().await?;
    let revoke_user_form: RevokeUserForm = serde_json::from_str(&r)?;
    match get_user_by_username(revoke_user_form.username)? {
        Some(mut user) => {
            user.two_factor = Some(false);
            puts_user(user)?;
            Ok(tide::Response::builder(200).header("content-type", "application/json").build())
        },
        None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
    }
}

async fn unrevoke_user(mut req: Request<()>) -> tide::Result {
    let r = req.body_string().await?;
    let revoke_user_form: RevokeUserForm = serde_json::from_str(&r)?;
    match get_user_by_username(revoke_user_form.username)? {
        Some(mut user) => {
            user.two_factor = Some(true);
            puts_user(user)?;
            Ok(tide::Response::builder(200).header("content-type", "application/json").build())
        },
        None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
    }
}

async fn list_users(req: Request<()>) -> tide::Result {
    match req.header("authorization") {
        Some(bearer) => {
            let token = bearer.last().to_string();
            let check = verify_user(token).await?;
            match check {
                Some(_) => {
                    let users = get_users(&DB)?;
                    let j = json!({"users": users}).to_string();
                    Ok(tide::Response::builder(200).body(j).header("content-type", "application/json").build())
                },
                None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
            }
        },
        None => Ok(tide::Response::builder(401).header("content-type", "application/json").build())
    }
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let configure = env_var_config();

    let cors = CorsMiddleware::new()
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
        .allow_headers("authorization".parse::<HeaderValue>().unwrap())
        .allow_origin(Origin::from(configure.origin))
        .allow_credentials(false);

    let mut app = tide::new();
    app.with(driftwood::DevLogger);
    app.with(cors);
    app.at("/").get(health);
    app.at("/").head(health);
    app.at("/create_user").post(create_user);
    app.at("/login").post(login_user);
    app.at("/userinfo").get(get_user);
    app.at("/update_user").post(update_user);
    app.at("/create_qr").get(create_qr);
    app.at("/create_totp").post(create_totp);
    app.at("/password_reset").post(password_reset);
    app.at("/insert").post(insert_event);
    app.at("/sse").get(sse);
    app.at("/revoke_user").post(revoke_user);
    app.at("/unrevoke_user").post(unrevoke_user);
    app.at("/list_users").post(list_users);

    let ip = format!("0.0.0.0:{}", configure.port);

    if configure.secure && configure.auto_cert {
        app.listen(
            tide_rustls::TlsListener::build().addrs("0.0.0.0:443").acme(
                AcmeConfig::new(vec![configure.domain]))
            )
            .await?;
    } else if configure.secure && !configure.auto_cert {
        app.listen(
            tide_rustls::TlsListener::build()
                .addrs("0.0.0.0:443")
                .cert(configure.cert_path)
                .key(configure.key_path),
        )
        .await?;
    } else {
        app.listen(ip).await?;
    }

    Ok(())
}
