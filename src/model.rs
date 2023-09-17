use crate::response::FilteredUser;
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: String,
    pub photo: String,
    pub verified: bool,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterUserSchema {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginUserSchema {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HealthCheckResponse {
    pub status: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct GetMeResponse {
    pub status: &'static str,
    pub data: UserData,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserData {
    pub user: FilteredUser,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LoginUserResponse {
    pub status: &'static str,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RegisterUserResponse {
    pub status: &'static str,
    pub data: UserData,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Response {
    pub status: &'static str,
    pub message: String,
}
