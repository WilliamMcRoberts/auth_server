use crate::{
    jwt_auth,
    model::{
        GetMeResponse, HealthCheckResponse, LoginUserResponse, LoginUserSchema,
        RegisterUserResponse, RegisterUserSchema, Response, TokenClaims, User, UserData,
    },
    response::FilteredUser,
    AppState,
};
use actix_web::{
    cookie::{time::Duration as ActixWebDuration, Cookie},
    get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{prelude::*, Duration};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use sqlx::Row;
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

use utoipa_rapidoc::RapiDoc;
use utoipa_redoc::{Redoc, Servable};

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        email: user.email.to_owned(),
        name: user.name.to_owned(),
        photo: user.photo.to_owned(),
        role: user.role.to_owned(),
        verified: user.verified,
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}

pub fn config(conf: &mut web::ServiceConfig) {
    let openapi = ApiDoc::openapi();

    let base_scope = web::scope("")
        .service(Redoc::with_url("/redoc", openapi.clone()))
        .service(RapiDoc::new("/api-docs/openapi.json").path("/rapidoc"))
        .service(register_user_handler)
        .service(login_user_handler)
        .service(logout_handler)
        .service(get_me_handler)
        .service(health_checker_handler)
        .service(
            SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", openapi.clone()),
        );

    conf.service(base_scope);
}

#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "Login User Endpoint",
    request_body(content = LoginUserSchema, description = "Credentials to log in to your account", example = json!({"email": "johndoe@example.com","password": "password123"})),
    responses(
        (status = 200, description= "Login User", body = LoginUserResponse),       
        (status=400, description= "Error", body= Response ),
    ),
)]
#[post("/auth/login")]
async fn login_user_handler(
    body: web::Json<LoginUserSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", body.email)
        .fetch_optional(&data.db)
        .await
        .unwrap();

    let is_valid = query_result.to_owned().map_or(false, |user| {
        let parsed_hash = PasswordHash::new(&user.password).unwrap();
        Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed_hash)
            .map_or(false, |_| true)
    });

    if !is_valid {
        return HttpResponse::BadRequest()
            .json(json!({"status": "fail", "message": "Invalid email or password"}));
    }

    let user = query_result.unwrap();

    let now = Utc::now();

    let iat = now.timestamp() as usize;

    let exp = (now + Duration::minutes(60)).timestamp() as usize;

    let claims: TokenClaims = TokenClaims {
        sub: user.id.to_string(),
        exp,
        iat,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(data.env.jwt_secret.as_ref()),
    )
    .unwrap();

    let cookie = Cookie::build("token", token.to_owned())
        .path("/")
        .max_age(ActixWebDuration::new(60 * 60, 0))
        .http_only(true)
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(json!({"status": "success", "token": token}))
}

#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "Register User Endpoint",
    request_body(content = RegisterUserSchema, description = "Credentials for your new account", example = json!({"name": "John Doe","email": "johndoe@example.com","password": "password123"})),
    responses(
        (status = 200, description= "Register User", body = RegisterUserResponse),       
        (status=400, description= "Error", body= Response ),
    ),
)]
#[post("/auth/register")]
async fn register_user_handler(
    body: web::Json<RegisterUserSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(body.email.to_owned())
        .fetch_one(&data.db)
        .await
        .unwrap()
        .get(0);

    if exists {
        return HttpResponse::Conflict().json(
            serde_json::json!({"status": "fail","message": "A user with that email already exists"}),
        );
    }

    let salt = SaltString::generate(&mut OsRng);

    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .expect("Error while hashing password")
        .to_string();

    let query_result = sqlx::query_as!(
        User,
        "INSERT INTO users (name,email,password) VALUES ($1, $2, $3) RETURNING *",
        body.name.to_string(),
        body.email.to_string().to_lowercase(),
        hashed_password
    )
    .fetch_one(&data.db)
    .await;

    match query_result {
        Ok(user) => {
            let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "user": filter_user_record(&user)
            })});

            return HttpResponse::Ok().json(user_response);
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", e)}));
        }
    }
}

#[utoipa::path(
    get,
    path = "/auth/logout",
    tag = "Logout User Endpoint",
    responses(
        (status = 200, description= "Logout Current Logged In User", body = Response),       
    ),
)]
#[get("/auth/logout")]
async fn logout_handler(_: jwt_auth::JwtMiddleware) -> impl Responder {
    let cookie = Cookie::build("token", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(json!({"status": "success", "message": "Successfully logged out"}))
}

#[utoipa::path(
    get,
    path = "/users/me",
    tag = "Get Authenticated User Endpoint",
    responses(
        (status = 200, description= "Get Current Authenticated Filtered User", body = GetMeResponse),       
    ),
)]
#[get("/users/me")]
async fn get_me_handler(
    req: HttpRequest,
    data: web::Data<AppState>,
    _: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let ext = req.extensions();
    let user_id = ext.get::<uuid::Uuid>().unwrap();

    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_one(&data.db)
        .await
        .unwrap();

    let json_response = serde_json::json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": filter_user_record(&user)
        })
    });

    HttpResponse::Ok().json(json_response)
}

#[utoipa::path(
    get,
    path = "/healthchecker",
    tag = "Health Checker Endpoint",
    responses(
        (status = 200, description= "Authenticated User", body = HealthCheckResponse),       
    )
)]
#[get("/healthchecker")]
async fn health_checker_handler() -> impl Responder {
    const MESSAGE: &str = "JWT Authentication in Rust using Actix-web, Postgres, and SQLX";

    HttpResponse::Ok().json(json!({"status": "success", "message": MESSAGE}))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        health_checker_handler,
        get_me_handler,
        login_user_handler,
        register_user_handler,
        logout_handler,
    ),
    components(
        schemas(FilteredUser, UserData, HealthCheckResponse, GetMeResponse, LoginUserSchema, LoginUserResponse, RegisterUserSchema, RegisterUserResponse, Response),
    ),
    tags(
        (name = "Rust Auth Server With Actix Web", description = "Authentication in Rust Endpoints")
    ),
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        )
    }
}
