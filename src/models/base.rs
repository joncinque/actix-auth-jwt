//! All User info, to be implemented by custom User classes

use {
    serde::{de::DeserializeOwned, Deserialize, Serialize},
    std::{
        fmt::{Debug, Display},
        hash::Hash,
    },
    validator::Validate,
};

/// Different states that a user could be in,
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Status {
    Confirmed,
    Unconfirmed,
    Suspended,
    Deleted,
}

/// Main trait to be implemented by library users.
/// Any fields can be included, as long as there are ways to serialize,
/// deserialize, copy, and update the User.  Everything else is templated based
/// on this User, so the system makes good use of the type-checker.
pub trait User
where
    Self: Clone + Serialize + DeserializeOwned + Send + Sync,
{
    /// User-provided key.  This could be a username or email address, and must
    /// be unique for the UserRepo to work.
    type Key: Clone + Eq + Hash + Display + From<String> + Send + Sync;
    /// System-generated id, assigned to a User on creation, likely using the
    /// generate_id function.  This Id is passed around to any other parts of
    /// the system that need to access the User's info.
    type Id: Serialize + DeserializeOwned + Clone + Eq + Hash + Display + From<String> + Send + Sync;

    /// Generate a new random Id, usually to be assigned to a created User.
    fn generate_id() -> Self::Id;

    /// Get the User's human-readable key, used for database interaction
    fn key_field() -> &'static str;
    fn key(&self) -> &Self::Key;
    /// Get the User's machine-generated id, used for database interaction
    fn id_field() -> &'static str;
    fn id(&self) -> &Self::Id;

    /// Get the User's status, used for confirming users
    fn status_field() -> &'static str;
    fn status(&self) -> &Status;
    fn set_status(&mut self, status: Status);

    /// Get User password, however it was saved in the system.  Typically, the
    /// UserRepo or Service will hash it, but the User does not need to know
    /// that.
    fn password_field() -> &'static str;
    fn password(&self) -> &str;
    fn set_password(&mut self, hash: String);

    /// An email is required for sending messages, be it registration confirmation,
    /// password reset, or anything else.
    fn email(&self) -> &str;

    /// A data transfer object type to be defined for creating a new User on
    /// registration.  If only email and password is required to create a User,
    /// those should be the only fields in the DTO.
    type RegisterDto: DeserializeOwned + Validate;
    fn from(registration: Self::RegisterDto) -> Self;

    /// A data transfer object type for performing a type-safe update on an
    /// existing User.  This should likely contain all of the fields in the
    /// User, except for the password, id, and anything else that should NOT
    /// be modifiable.
    type UpdateDto: DeserializeOwned + Validate;
    fn update(&mut self, update: Self::UpdateDto);
}
