# actix-auth-jwt
Sample actix-web application for user management using extras for JWT authentication

NOTE: This repo is currently a work-in-progress, so it is not ready for any 
production use whatsoever.  Either way, feel free to reach out with any
questions or concerns.

## Prereqs

* Rust 1.42
* MongoDB 4.2
* LLVM / Clang for `argonautica`: `sudo apt install clang`

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
FROM_EMAIL=
MONGO_URI=
MONGO_DB=
MONGO_COLLECTION=
REDIS_URI=
```
* `HASHER_SECRET_KEY`: randomly generated string of letters and numbers 
* `FROM_EMAIL`: valid email address used for sending emails to users
* (Optional) MongoDB setup
  - `MONGO_URI`: uri of mongo instance, can use the full uri spec including
user / password / auth db
  - `MONGO_DB`: db name
  - `MONGO_COLLECTION`: collection name for storing users
* (Optional) Redis setup

## Testing

`cargo test`

## TODO Items

* `lettre` update to version 1 or 0.10 with new email builder
* Transition email sending to async, NOTE that `lettre` currently has no plans for this
* Update password hashing to async
* Use `tokio::sync::RwLock` once they no longer require `Sized`
