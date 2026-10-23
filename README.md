# MichuStudio — website + account server

Website and API bundled into one Render Node web service. The UI is mobile-first and includes Spanish, Brazilian Portuguese and English. The tone is casual on purpose, not corporate.

## Included

- Home, Games/Downloads, Wiki, News, Forum and Community pages.
- Login and registration using the existing `/login`, `/register`, `/auth/me` and bearer-token API.
- Editable account profile, avatar, banner, privacy settings and password change.
- Account directory, friend requests, friends list and internal inbox/messages.
- Server-backed forum posts and comments, with moderation and rate limits.
- Private `/admin` dashboard with a separate admin session cookie, account deletion, username change, bans, roles, profile reset and admin messages.
- Parameterized SQL for forum queries and the existing account queries; user input is not interpolated into SQL.

## Before deployment

1. Use the same PostgreSQL database as the existing account service, or a compatible database with the existing `users` data. **Do not point this at a blank database if you need to preserve accounts.**
2. In Render, configure the required environment variables listed below. Never place any secret in `public/`, `Juegos.json`, GitHub's public history or frontend JavaScript.
3. Use `LEGACY_AUTH=false`, `ALLOW_ADMIN_KEY_HEADER=false`, and `DB_SSL_INSECURE=false`.
4. Set `ADMIN_KEY` to a private random 32-letter value (run `npm run generate-admin-key` to generate one locally). `OPENAI_API_KEY` is required by the current server for moderation.
5. **If deploying this as a second service against the existing database, copy the current production `TOKEN_SECRET` exactly** so current session tokens keep working. Do not rotate it casually; changing it logs users out. If this replaces the current service, keep its existing value too.
6. The attached `server.js` did not include a real APK. Put the real build at `games/Michiverse/Michiverse.apk` and then set `available: true` in `Juegos.json` before advertising the download.
7. Test on a preview service before replacing the current production server. This server runs schema initialization and migrations at startup.

## Required environment variables

- `DATABASE_URL` — PostgreSQL connection URL.
- `OPENAI_API_KEY` — server-side moderation key.
- `ADMIN_KEY` — private admin login secret (recommended exactly 32 letters).
- `TOKEN_SECRET` — separate random HMAC signing secret, at least 32 characters.

Optional variables are documented in `.env.example`. Render supplies `PORT` automatically.

## Local run

```sh
npm install
cp .env.example .env
# Fill .env locally; never commit it.
npm start
```

Visit `http://localhost:3000` and `http://localhost:3000/admin`.

## AccountKey change

Normal profile editing, avatar/banner upload and region changes now rely on the authenticated bearer token plus the server-side ownership check. The account key generation/storage remains for backward compatibility with any external game integration; the website does not send it for routine profile edits.

## Routes added

- `GET /forum/posts`
- `POST /forum/posts`
- `GET /forum/posts/:id/comments`
- `POST /forum/posts/:id/comments`
- `POST /admin/users/:id/username`

The existing friends and internal mail endpoints are reused by the website.
