# actix-auth-jwt
Sample actix-web application for user management using extras for JWT authentication

## Prereqs

* Rust 1.42
* MongoDB 4.2
* LLVM / Clang for `argonautica`: `sudo apt install clang`

## Dependencies

* `actix-web`, `actix-http`, `actix-rt`: all main actix components
* `argonautica`: for argon2 password hashing
* `mongodb`, `bson`: requirements for db interaction
* `dotenv`: managing secrets
* `log`, `env_logger`: easy logging to stdout
* `serde`, `serde_json`: easy (de)serialization of structs
* `failure`: for digestible error messages
* `uuid` v4 with `serde`: generating random user ids and serializing to string
* `jsonwebtoken`: creating JWTs on login, validating authenticated routes

## Building

`cargo build`

## Running

* Setup your .env file with the following
```bash
MONGO_URI=http://localhost:27017
MONGO_DB=app
MONGO_COLLECTION=users
SECRET_KEY=some_randomly_generated_string_of_letters_and_numbers
```
* `cargo run` 

## Testing

`cargo test`
