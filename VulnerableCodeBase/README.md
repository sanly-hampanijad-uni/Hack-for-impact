# Vulnerability Generation Agent API

A small username-and-password login service written in Go. User accounts and sessions are kept in memory, so they are cleared when the server restarts. Passwords are stored as bcrypt hashes.

## Run

```sh
go run .
```

The server listens on port `8080` by default. Set the `PORT` environment variable to use a different port.

## Routes

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Returns the server health status. |
| `GET` | `/api/v1` | Returns API name and available routes. |
| `POST` | `/api/v1/register` | Register with a JSON `username` and `password`; creates a session. |
| `POST` | `/api/v1/login` | Sign in with a JSON `username` and `password`. |
| `POST` | `/api/v1/logout` | Sign out and invalidate the current session. |
| `GET` | `/api/v1/me` | Returns the signed-in username. |

The landing page at `/` includes sign-in and registration forms. Unknown browser paths display an HTML not-found page; unknown API paths return JSON `404` responses. Unsupported methods return `405` with an `Allow` header. Usernames are 3-32 letters, numbers, underscores, or hyphens. Passwords must be 8-72 bytes.

This in-memory service is a development starter, not production authentication storage. Accounts and sessions do not survive a restart.

## Test

```sh
go test ./...
```