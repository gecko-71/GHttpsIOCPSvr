# DEMO 02: JWT Security & WAF Protection Server

A REST API gateway providing advanced protection against web attacks (WAF), request rate limiting, and JWT-based authorization with role-based access control (RBAC).

---

## Key Features
- **WAF Threat Inspection**: Detects and blocks SQL Injection and Cross-Site Scripting (XSS) attack attempts.
- **Rate Limiter**: Limits requests per IP to 10 req/sec. Exceeding the limit returns HTTP `429 Too Many Requests`.
- **JWT Authorization (RBAC)**: `/api/login` issues tokens with `admin` or `user` roles. `/api/protected/*` endpoints enforce role checks.

## API Endpoints
| Method | Path | Description | Auth |
|---|---|---|---|
| `POST` | `/api/login` | Obtain JWT token (`admin/admin123` or `user/user123`) | Public |
| `GET` | `/api/protected/profile` | Get user profile | JWT Required |
| `GET` | `/api/protected/admin` | Admin dashboard | JWT + Admin role |
| `GET` | `/api/status` | Server and WAF status | Public |

## Getting Started
1. Run `JwtSecurityWafServer.exe`.
2. Open `https://localhost:8082/` in your browser.
