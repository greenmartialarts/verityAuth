# Authentication Service

A standalone, high-performance authentication service written in **Rust**, powered by **Axum**, **Tokio**, **SQLx**, and **Neon PostgreSQL**.

## Features

- **Fast & Stateless**: Secure JWT authentication via Ed25519 (EdDSA) signatures.
- **Argon2id Hashing**: Industry-standard password hashing parameter configurations.
- **Refresh Token Rotation**: Automatic token revocation and replacement on rotation or password modification.
- **IP Rate Limiting**: Built-in in-memory rate limiting (max 10 login attempts/minute per IP).
- **Anti-Timing & Delay Protection**: Failed login delays to prevent email enumeration and brute forcing.
- **Embedded Migrations**: Applies database schemas automatically on startup.

---

## Setup & Run

### 1. Requirements
Ensure you have **Rust** installed on your system.

### 2. Generate Ed25519 Cryptographic Keys
Run the following commands in the root of the project to generate the required PEM key pair:
```bash
openssl genpkey -algorithm ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

### 3. Environment Variables
Configure your database URL and settings in `.env`:
```env
DATABASE_URL=postgresql://neondb_owner:password@ep-host-pooler.region.neon.tech/neondb?sslmode=require
JWT_PRIVATE_KEY=./private.pem
JWT_PUBLIC_KEY=./public.pem
JWT_ACCESS_EXPIRATION=600
JWT_REFRESH_EXPIRATION=2592000
```

### 4. Build & Run
Run the service locally:
```bash
cargo run
```
The server will start listening on `0.0.0.0:8080`.

---

## Testing & Verification

We have created an automated integration test script that starts the service, performs a complete lifecycle (registration, login, profile check, token rotation, password change, lockout checks, logout), and shuts down the service.

Run the test suite:
```bash
./verify.sh
```
