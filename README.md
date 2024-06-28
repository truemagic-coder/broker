## Broker - Real-time BaaS (Backend as a Service)

[![crates.io](https://img.shields.io/crates/v/broker)](https://crates.io/crates/broker)

### Purpose

The purpose of this service is to be your real-time BaaS (Backend as a Service). 

Broker is a SSE message broker that requires you write no backend code to have a full real-time API.

Broker is born from the need that rather than building a complex REST API with web-sockets and a SQL database to provide reactive web forms (like for React) there must be a simpler way.

Broker follows an insert-only/publish/subscribe paradigm rather than a REST CRUD paradigm. 

Broker also provides full identity services using JWT, HTTP Basic, Two Factor, and TOTP.

Broker is a competitor to [Firebase](https://firebase.google.com/), [Parse Server](https://github.com/parse-community/parse-server), [Auth0](https://auth0.com), [AWS Cognito](https://aws.amazon.com/cognito/), [AWS IAM](https://aws.amazon.com/iam/), [AWS SimpleDB](https://aws.amazon.com/simpledb/), and [AWS SNS](https://aws.amazon.com/sns/).

### Features

* Very performant with almost no CPU and memory usage
* Under 1000 lines of code
* Secure Real-time Event Stream via SSE - requires the use of [broker-client](https://www.npmjs.com/package/broker-client)
* Supports CORS
* JSON API
* Add users with admin token permission
* Multi-tenant
* Supports SSL - full end-to-end encryption
* Provides user authentication with JWTs or HTTP Basic
* Issues JWTs for authentication (username) and authorization (scopes) for external services
* Verify endpoint for external services like [portal](https://crates.io/crates/portal) and [files](https://crates.io/crates/files)
* Secure password storage with Argon2 encoding
* Uses Global NTP servers and doesn't rely on your local server time for JWT expiry timing and Two Factor timing
* Sync latest events on SSE client connection
* Auto-provision and renews SSL cert via LetsEncrypt or use your own SSL cert
* User Management API endpoints (create, revoke, unrevoke, list, get, update)
* User Email Address Validation (regex and blacklist check against throwaway emails) using [mailchecker](https://crates.io/crates/mailchecker)
* Password Strength Checker using [zxcvbn](https://crates.io/crates/zxcvbn)
* Two Factor Authenication with QR code generation for Google Authenticator, Authy, etc.
* Secure user password resets with a TOTP with a configurable time duration

### How it works

In Broker you create a user, login, then insert an event with its data. Broker then publishes the event via SSE.

When the client first subscribes to the SSE connection all the latest events and data is sent to the client. Combined with sending the latest event via SSE when subscribed negates the necessity to do any GET API requests in the lifecycle of an event.

The side-effect of this system is that the latest event is the schema. This is pure NoSQL as the backend is agnostic to the event data.

### Recommeded Services/Libraries to use with Broker
* [broker-client](https://www.npmjs.com/package/broker-client) - the official front-end client for broker
* [broker-hook](https://www.npmjs.com/package/broker-hook) - the official react hook for broker
* [React Hook Form](https://react-hook-form.com/) - Best form library for React
* [React Debounce Input](https://www.npmjs.com/package/react-debounce-input) - React input for Real-time Submission (Edit in Place forms)

### Use

#### Step 1 - create a user

```html
POST /create_user 
```
- public endpoint
```json
{
    "username": "bob", 
    "password": "password1", 
    "admin_token": "letmein", 
    "tenant_name": "tenant_1",
    "email": "bob@hotmail.com",
    "two_factor": true,
    "scopes": ["news:get", "news:post"],
    "data": {
        "name": "Robert Wieland",
        "image": "https://img.com/bucket/123/123.jpg"
    }
}
```
- `admin_token` is required and can be set in the command args - it is for not allowing everyone to add a user - the default is `letmein`
- `email`, `scopes`, `two_factor`, and `data` are optional fields

will return `200` or `500` or `400`


#### For JWT Auth: Step 2 - login with the user

```html
POST /login 
```
- public endpoint
```json
{
    "username": "bob", 
    "password": "password1",
    "totp": "123456",
}
```
- `totp` is required if two factor is enabled for the user - if not the field can be omitted

will return: `200` or `500` or `400` or `401`

200 - will return a JWT
```json
{
    "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTc2NzQ5MTUsImlhdCI6MTYxNzU4ODUxNSwiaXNzIjoiRGlzcGF0Y2hlciIsInN1YiI6ImZvbyJ9.OwiaZJcFUC_B0CA0ffRZVTWKRf5_vQ7vt5USNJEeKRE" 
}
```
- note: if you need to debug your JWT then visit [jwt.io](https://jwt.io)


#### Step 3 - connect to SSE

```html 
GET /sse
```
- authenticated endpoint (Authorization: Bearer {jwt}) or (Authorization: Basic {username:password})
- connect your sse-client to this endpoint using [broker-client](https://www.npmjs.com/package/broker-client)
- `note`: broker-client uses fetch as eventsource doesn't support headers

#### Step 4 - insert an event

```html
POST /insert 
```
- authenticated endpoint (Authorization: Bearer {jwt}) or (Authorization: Basic {username:password})
```json
{
    "event": "test", 
    "data": {
        "name": "robert",
        "image": "https://img.com/bucket/123/123.jpg"
    }
}
```

will return: `200` or `500` or `400` or `401`

#### Optional - verify user

```html
GET /verify
```
- authenticated endpoint (Authorization: Bearer {jwt}) or (Authorization: Basic {username:password})
- verifies that the user is authenticated on broker - used for external services like [portal](https://crates.io/crates/portal)

will return: `200` or `500` or `401`

200 - will return a biscuit public key, biscuit token, username, and JWT expiry for your microservice (use from_bytes to hydrate the key and token)
```json
{
    "key": [136,133,229,196,134,20,240,80,159,158,154,20,57,35,198,7,156,160,193,224,174,209,51,150,27,86,75,122,172,24,114,66],
    "token": [122,133,229,196,134,20,240,80,159,158,154,20,57,35,198,7,156,160,193,224,174,209,51,150,27,86,75,122,172,24,114,121],
    "expiry": 1618352841,
    "username": "bob",
    "scopes": ["news:get", "news:post"]
}
```

#### Optional - revoke user

```html
POST /revoke_user
```
- public endpoint
```json
{
    "admin_token": "letmein",
    "username": "bob"
}
```

will return: `200` or `500` or `400` or `401`
- note: revoked users cannot login

#### Optional - unrevoke user

```html
POST /unrevoke_user
```
- public endpoint
```json
{
    "admin_token": "letmein",
    "username": "bob"
}
```

will return: `200` or `500` or `400` or `401`

#### Optional - list users

```html
POST /list_users
```
- public endpoint
```json
{
    "admin_token": "letmein"
}
```

will return: `200` or `500` or `400` or `401`

200 - will return an array of objects
```json
[
    {
        "id": "69123c04-fa42-4193-a6c5-ab2fc27658b1",
        "password": "***",
        "totp": "***",
        "revoked": false,
        "tenant_name": "tenant_1",
        "username": "bob",
        "email": "bob@hotmail.com",
        "scopes": ["news:get", "news:post"],
        "data": {
            "name": "Robert Wieland",
            "image": "https://img.com/bucket/123/123.jpg"
        }
    }
]
```
- note: `email`, `scopes`, `two_factor`, and `data` can be `null`

#### Optional - get user

```html
POST /get_user
```
- public endpoint
```json
{
    "admin_token": "letmein",
    "username": "bob"
}
```

will return: `200` or `500` or `400` or `401`

200 - will return an array of objects
```json
{
    "id": "69123c04-fa42-4193-a6c5-ab2fc27658b1",
    "password": "***",
    "totp": "***",
    "revoked": false,
    "tenant_name": "tenant_1",
    "username": "bob",
    "email": "bob@hotmail.com",
    "scopes": ["news:get", "news:post"],
    "data": {
        "name": "Robert Wieland",
        "image": "https://img.com/bucket/123/123.jpg"
    }
}
```
- note: `email`, `scopes`, `two_factor`, and `data` can be `null`

#### Optional - update user

```html
POST /update_user
```
- public endpoint
```json
{
    "admin_token": "letmein",
    "username": "bob",
    "tenant_name": "tenant_2",
    "password": "new_password",
    "email": "bober@hotmail.com",
    "scopes": ["news:get", "news:post"],
    "data": {
        "name": "Robert Falcon",
        "image": "https://img.com/bucket/123/1234.jpg"
    }
}
```
- note: `tenant_name`, `password`, `email`, `scopes`, `data` are optional fields

will return: `200` or `500` or `400` or `401`

#### Optional - Health Check

```html
GET or HEAD /
```
- public endpoint

will return: `200`

#### Optional - generate two factor QR Code

```html
POST /create_qr
```
- public endpoint
```json
{
    "issuer": "Broker",
    "admin_token": "letmein",
    "username": "bob"
}
```
- note: put the name of your application in the issuer field
- note: the ID of the QR will be the user's username and your issuer field

will return: `200` or `500` or `400` or `401`

200 - will return the qr code in PNG format in base64
```json
{
    "qr": "dGhpc2lzYXN0cmluZw=="
}
```

#### Optional - create totp

```html
POST /create_totp
```
- public endpoint
```json
{
    "admin_token": "letmein",
    "username": "bob"
}
```
will return: `200` or `500` or `400` or `401`

200 - will return the totp
```json
{
    "totp": "622346"
}
```
- note: these TOTPs can only be used with the password reset endpoint

#### Optional - user password reset

```html
POST /password_reset
```
- public endpoint
```json
{
    "totp": "622346",
    "username": "bob",
    "password": "password1"
}
```

will return: `200` or `500` or `400` or `401`

### Install

``` cargo install broker ```

- the `origin` can be passed in as a flag - default `*`
- the `port` can be passed in as a flag - default `8080` - can only be set for unsecure connections
- the `jwt_expiry` for jwts can be passed in as a flag in seconds - default `86400`
- the `jwt_secret` for jwts should be passed in as a flag - default `secret`
- the `secure` flag for https and can be true or false - default `false`
- the `auto_cert` flag for an autorenewing LetsEncrypt SSL cert can be true or false - requires a resolvable domain - default `true` 
- the `key_path` flag when `auto_cert` is `false` to set the SSL key path for your own cert - default `certs/private_key.pem`
- the `cert_path` flag when `auto_cert` is `false` to set the SSL cert path for your own cert - default `certs/chain.pem`
- the `certs` flag is the storage path of LetsEncrypt certs - default `certs`
- the `db` flag is the path where the embedded database will be saved - default `db`
- the `domain` flag is the domain name (e.g. api.broker.com) of the domain you want to register with LetsEncrypt - must be fully resolvable 
- the `admin_token` flag is the password for the admin to add users - default `letmein`
- the `password_checker` flag enables zxcvbn password checking - default `false`
- the `totp_duration` flag is the duration of the TOTP for user generated password reset - default 300 seconds (5 min)
- production example: `./broker --secure="true" --admin_token="23ce4234@123$" --jwt_secret="xTJEX234$##$" --domain="api.broker.com" --password_checker="true"`

### Service

There is an example `systemctl` service for Ubuntu called `broker.service` in the code

### TechStack

* [Tide](https://crates.io/crates/tide)
* [RocksDB](https://crates.io/crates/rocksdb)

### Inspiration

* [Auth0](https://auth0.com)
* [React Hooks](https://reactjs.org/docs/hooks-intro.html)
* [Meteor](https://meteor.com)
* [MongoDB](https://www.mongodb.com/)
* [Pusher](https://pusher.com)
* [Event Sourcing](https://microservices.io/patterns/data/event-sourcing.html)
* [Best in Place](https://github.com/bernat/best_in_place)
* [Brock Whitten](https://www.youtube.com/watch?v=qljYMEfVukU)
