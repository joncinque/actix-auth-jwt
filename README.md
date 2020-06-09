# actix-auth-jwt
Sample actix-web application for user management using extras for JWT authentication

NOTE: This repo is currently a work-in-progress, so it is not ready for any 
production use whatsoever.  Either way, feel free to reach out with any
questions or concerns.

## Design

### Overview

This project is a plug-in for web authentication within the excellent
[actix](https://actix.rs/) framework in Rust, fully embracing async from the 
ground up.  [JWTs](https://jwt.io/) represent user claims, most simply used to
make authorize a request to a protected route.

If you have an existing web server using `actix`, or you want to start using
Rust in a web environment, this package may be for you!

You can include this as an actix `App` within your server, providing routes for:
* User creation, including email confirmation
* Password reset through email
* Password update
* Login to receive a new JWT pair
* Refresh to receive a new JWT pair, blacklisting previous token pair
* Logout to blacklist token pair
* User deletion
* Token validation / decoding

Additionally, you can add access token checking as a
[middleware](https://actix.rs/docs/middleware/) on your routes, apps, or
resources as needed.

### Configuration

Overall app configuration is handled through creation of an `AppConfig` struct
which handles how to create the main components:

* `UserRepo`: where the users are stored (files, database, in-memory, etc)
* `EmailSender`: transport for sending emails to users, currently only Stub and 
InMemory are exposed for testing
* `PasswordHasher`: for now, just the secret key for the argon2 password hasher
and verifier
* `JwtBlacklist`: where blacklisted tokens are stored, allowing to store, check,
blacklist, and flush tokens
* `JwtAuthenticator`: configure how to create the JWT pair, e.g. token
lifetimes, hashing secret

### User

Only `SimpleUser` is provided out of the box, mainly for testing purposes,
youcan simply implement the `User` trait containing all of the fields that
you care about.

Note: there is a requirement for both a `Key` and an `Id`. The `Key` is some 
user-provided key, e.g. email address or username. The `Id` is a
system-generated identifier, e.g. uuid.  You can use the `Id` in different
parts of your system.

### JWTs

JSON Web Tokens are simply a standard for signed or encrypted base-64 encoded
JSON, and thus they can be used for all sorts of applications.

In this package, a pair of access and refresh token is issued on login.
These tokens have a lifetime defined in the configuration.  The access token is 
designed to be short-lived and reused for every API call.  Once it expires, or 
whenever desired, the refresh token is used to acquire a new access and refresh 
token pair.

Once a refresh token is used, it becomes blacklisted to avoid being reused
in the future.

More information can be found at this excellent
[guide by Auth0](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/).


## Prereqs

* Rust 1.42
* MongoDB 4.2

## Dependencies

* `actix-web`, `actix-http`, `actix-rt`: all main actix components
* `mongodb`, `bson`: requirements for db interaction
* `dotenv`, `dotenv-codegen`: managing production secrets
* `log`, `env_logger`: easy logging to stdout
* `serde`, `serde_json`: easy (de)serialization of structs
* `failure`: for digestible error messages
* `uuid` with `serde`: generating random user ids and serializing to string
* `jsonwebtoken`: creating JWTs on login, validating authenticated routes
* `rust-argon2`: for argon2 password hashing

## Building

`cargo build`

## .env setup

* Setup a `.env` file with the following
```bash
HASHER_SECRET_KEY=
JWT_SECRET_KEY=
FROM_EMAIL=
MONGO_URI=
MONGO_DB=
MONGO_COLLECTION=
```
* `HASHER_SECRET_KEY`: randomly generated string of letters and numbers,
used for hashing user passwords
* `JWT_SECRET_KEY`: randomly generated string of letters and numbers, used for
signing JWTs
* `FROM_EMAIL`: valid email address used for sending emails to users
* `MONGO_URI`: uri of mongo instance, can use the full uri spec including
user / password / auth db
* `MONGO_DB`: db name
* `MONGO_COLLECTION`: collection name for storing users

## Testing

`cargo test`

## TODO Items

* Expose all `lettre` transports in EmailConfig
* Expose more password hashers
* Update `lettre` to version 1 or 0.10 with new email builder
* Transition `lettre` email sending to async once tokio is supported
* Update password hashing to async, which is currently very slow
* Use `tokio::sync::RwLock` instead of a normal `RwLock` once they no longer
require `Sized`
* Add simplest example for using provided types
* Add example with customized `AppConfig`
* Add example with customized `User` type and user update routes
* Add example with customized `UserRepo` for another database provider
* Make `JwtPair` generic for different token types (sliding, access-only, etc)
* Add Redis `UserRepo` implementation
* Add Diesel `UserRepo` implementation
* Break out different database implementations into features
