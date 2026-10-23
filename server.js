const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");
const multer = require("multer");
const sharp = require("sharp");

function log(message, value = "") {
    console.log(
        value !== ""
            ? `[MichuStudio] ${message}: ${value}`
            : `[MichuStudio] ${message}`
    );
}

function readEnv(name, fallback = "") {
    const value = process.env[name];
    return value === undefined || value === "" ? fallback : value;
}

const missingEnv = [];

function requireEnv(name, minLength) {
    const value = readEnv(name);

    if (!value || value.length < minLength) {
        missingEnv.push(`${name} (minimo ${minLength} caracteres)`);
        return "";
    }

    return value;
}

function readNumberEnv(name, fallback, min) {
    const value = Number(readEnv(name, String(fallback)));

    if (!Number.isFinite(value) || value < min) {
        console.error(`[MichuStudio] ${name} invalido (minimo ${min})`);
        process.exit(1);
    }

    return value;
}

const PORT = readNumberEnv("PORT", 3000, 1);
const DATABASE_URL = requireEnv("DATABASE_URL", 10);
const OPENAI_API_KEY = requireEnv("OPENAI_API_KEY", 10);
const ADMIN_KEY = requireEnv("ADMIN_KEY", 24);
const TOKEN_SECRET = requireEnv("TOKEN_SECRET", 32);
const SERVICE_KEY = readEnv("SERVICE_KEY");

if (missingEnv.length > 0) {
    console.error(`[MichuStudio] Faltan variables de entorno: ${missingEnv.join(", ")}`);
    process.exit(1);
}

if (SERVICE_KEY && SERVICE_KEY.length < 32) {
    console.error("[MichuStudio] SERVICE_KEY debe tener minimo 32 caracteres");
    process.exit(1);
}

const TOKEN_TTL_MS = readNumberEnv("TOKEN_TTL_SECONDS", 604800, 60) * 1000;
const MAX_SESSION_MS = readNumberEnv("MAX_SESSION_SECONDS", 2592000, 3600) * 1000;
const LEGACY_AUTH = readEnv("LEGACY_AUTH", "false") === "true";
const ALLOW_ADMIN_KEY_HEADER = readEnv("ALLOW_ADMIN_KEY_HEADER", "false") === "true";
const DB_SSL_INSECURE = readEnv("DB_SSL_INSECURE", "false") === "true";
const MODERATE_MAIL = readEnv("MODERATE_MAIL", "true") === "true";
const CORS_ORIGINS = readEnv("CORS_ORIGINS")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

if (LEGACY_AUTH) {
    console.warn("[MichuStudio] AVISO: LEGACY_AUTH activo, cualquiera con un userId puede actuar como ese usuario");
}

if (ALLOW_ADMIN_KEY_HEADER) {
    console.warn("[MichuStudio] AVISO: ALLOW_ADMIN_KEY_HEADER activo");
}

if (DB_SSL_INSECURE) {
    console.warn("[MichuStudio] AVISO: DB_SSL_INSECURE activo, no se valida el certificado de la base de datos");
}

const BCRYPT_ROUNDS = 12;
const ACCOUNT_KEY_ROUNDS = 10;
const AVATAR_SIZE = 144;
const BANNER_WIDTH = 360;
const BANNER_HEIGHT = 144;
const DESCRIPTION_MAX = 300;
const DESCRIPTION_MAX_LINES = 5;
const ROLES = ["Creator", "User", "Admin"];
const DEFAULT_ROLE = "User";
const ACCENT_REGEX = /^#[0-9A-F]{6}$/;
const STATUS_MAX = 60;
const MAX_BLOCKS = 200;
const MAX_OUTGOING_REQUESTS = 50;
const MAX_INCOMING_REQUESTS = 100;
const MAX_BADGES = 8;
const BADGE_REGEX = /^[a-z0-9_]{1,24}$/;
const MAX_INPUT_PIXELS = 24000000;
const MAX_FRIENDS = 200;
const MAX_MAILS_PER_USER = 200;
const MAX_ADMIN_SESSIONS = 10;
const ONLINE_WINDOW_MS = 10000;

const USER_ID_REGEX = /^[A-Za-z0-9_-]{1,64}$/;
const USERNAME_REGEX = /^[A-Za-z0-9\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u017F_.\- ]+$/u;
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF]/g;
const CONTROL_CHARS_TEST = new RegExp(CONTROL_CHARS.source);

sharp.concurrency(2);
sharp.cache({ memory: 64, files: 0, items: 50 });

class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

const BLOCKED_USERNAME_TERMS = [
    "porn", "porno", "pornografia", "pornography", "pornografico", "pornografica",
    "xxx", "nsfw", "nude", "nudes", "nudity", "sex", "sexo", "sexy", "sexual",
    "explicit", "onlyfans",
    "puta", "puto", "putas", "putos", "mierda", "merda", "porra", "caralho",
    "foda", "foder", "fodendo", "buceta", "boceta", "piroca", "rola", "pica",
    "verga", "cono", "joder", "jodido", "jodida", "chingar", "chingado",
    "chingada", "pendejo", "pendeja", "cabron", "cabrona", "cagona", "cagon",
    "cagada", "cagar", "cojones", "zorra", "maricon", "marica",
    "fuck", "fucking", "fucked", "shit", "bitch", "bastard", "dick", "cock",
    "pussy", "whore", "slut", "asshole", "motherfucker",
    "putain", "merde", "salope", "nique",
    "scheisse", "fick", "hurensohn", "arschloch",
    "cazzo", "stronzo", "puttana", "fanculo", "vaffanculo"
];

const BLOCKED_USERNAME_PATTERNS = [
    /p+[\W_]*o+[\W_]*r+[\W_]*n+/iu,
    /s+[\W_]*e+[\W_]*x+/iu,
    /x+[\W_]*x+[\W_]*x+/iu,
    /n+[\W_]*s+[\W_]*f+[\W_]*w+/iu,
    /n+[\W_]*u+[\W_]*d+[\W_]*e+/iu
];

const HOMOGLYPHS = {
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0456": "i",
    "\u0458": "j"
};

function normalizeForModeration(value) {
    let text = String(value || "").toLowerCase();

    text = text
        .normalize("NFKD")
        .replace(/\p{M}/gu, "")
        .replace(CONTROL_CHARS, "");

    text = text.replace(
        /[\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458]/gu,
        (char) => HOMOGLYPHS[char]
    );

    return text
        .replace(/0/g, "o")
        .replace(/[1!|]/g, "i")
        .replace(/3/g, "e")
        .replace(/[4@]/g, "a")
        .replace(/[5$]/g, "s")
        .replace(/7/g, "t");
}

const NORMALIZED_BLOCKED_TERMS = BLOCKED_USERNAME_TERMS
    .map(normalizeForModeration)
    .filter(Boolean);

function moderateUsernameLocally(username) {
    const original = String(username || "");

    if (CONTROL_CHARS_TEST.test(original)) {
        return { blocked: true, matched: "control_character" };
    }

    const normalized = normalizeForModeration(original);

    if (!normalized) {
        return { blocked: false, matched: "" };
    }

    for (const pattern of BLOCKED_USERNAME_PATTERNS) {
        if (pattern.test(normalized)) {
            return { blocked: true, matched: "pattern" };
        }
    }

    const words = normalized
        .replace(/[^a-z0-9]+/g, " ")
        .trim()
        .split(/\s+/)
        .filter(Boolean);

    const compact = words.join("");

    for (const term of NORMALIZED_BLOCKED_TERMS) {
        if (words.includes(term)) {
            return { blocked: true, matched: term };
        }

        if (term.length >= 4 && compact.includes(term)) {
            return { blocked: true, matched: term };
        }
    }

    return { blocked: false, matched: "" };
}

function now() {
    return Date.now();
}

function safeEqual(a, b) {
    const hashA = crypto.createHash("sha256").update(String(a ?? "")).digest();
    const hashB = crypto.createHash("sha256").update(String(b ?? "")).digest();
    return crypto.timingSafeEqual(hashA, hashB);
}

function cleanId(value) {
    return String(value ?? "").trim();
}

function isValidUserId(value) {
    return USER_ID_REGEX.test(String(value || ""));
}

function cleanText(value, maxLength) {
    return String(value ?? "")
        .replace(CONTROL_CHARS, "")
        .trim()
        .slice(0, maxLength);
}

function cleanUsername(value) {
    return cleanText(value, 64).normalize("NFKC").trim();
}

function generateUniqueId() {
    return String(crypto.randomInt(100000000, 999999999));
}

function generateAccountKey() {
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let randomPart = "";

    for (let i = 0; i < 12; i++) {
        randomPart += alphabet[crypto.randomInt(0, alphabet.length)];
    }

    return `Michiverse_Key_${randomPart}`;
}

function normalizeRegion(region) {
    return String(region || "").trim().toUpperCase();
}

function isValidRegion(region) {
    return /^[A-Z]{2}$/.test(region);
}

function normalizeMailType(type) {
    const value = String(type || "").trim();

    if (value === "Normal") {
        return "Normal";
    }

    if (value === "Warning") {
        return "Warning";
    }

    return null;
}

function normalizeRole(role) {
    const value = String(role || "").trim().toLowerCase();
    return ROLES.find((item) => item.toLowerCase() === value) || null;
}

function cleanDescription(value) {
    const text = String(value ?? "").replace(/\r\n?/g, "\n");

    return cleanText(text, DESCRIPTION_MAX * 2)
        .split("\n")
        .slice(0, DESCRIPTION_MAX_LINES)
        .map((line) => line.trim())
        .join("\n")
        .replace(/\n{3,}/g, "\n\n")
        .trim()
        .slice(0, DESCRIPTION_MAX);
}

function cleanStatus(value) {
    return cleanText(String(value ?? "").replace(/\s+/g, " "), STATUS_MAX);
}

function validatePassword(password) {
    if (password.length < 8) {
        return "Contrase\u00f1a muy corta";
    }

    if (Buffer.byteLength(password, "utf8") > 72) {
        return "Contrase\u00f1a muy larga";
    }

    return "";
}

const asyncHandler = (handler) => (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
};

const limiterStores = [];

function createLimiter({ windowMs, max, keyFn, message }) {
    const store = new Map();
    limiterStores.push(store);

    return function limiter(req, res, next) {
        const key = keyFn ? keyFn(req) : req.ip;
        const current = now();

        let entry = store.get(key);

        if (!entry || entry.resetAt <= current) {
            if (store.size > 100000) {
                store.delete(store.keys().next().value);
            }

            entry = { count: 0, resetAt: current + windowMs };
            store.set(key, entry);
        }

        entry.count += 1;

        if (entry.count > max) {
            res.setHeader("Retry-After", String(Math.ceil((entry.resetAt - current) / 1000)));
            return res.status(429).json({ error: message || "Demasiadas solicitudes" });
        }

        next();
    };
}

setInterval(() => {
    const current = now();

    for (const store of limiterStores) {
        for (const [key, entry] of store.entries()) {
            if (entry.resetAt <= current) {
                store.delete(key);
            }
        }
    }
}, 60000).unref();

const globalLimiter = createLimiter({ windowMs: 60000, max: 600 });

const loginLimiter = createLimiter({
    windowMs: 10 * 60000,
    max: 10,
    keyFn: (req) => `${req.ip}:${cleanUsername(req.body?.username).toLowerCase()}`,
    message: "Demasiados intentos. Espera unos minutos."
});

const loginIpLimiter = createLimiter({
    windowMs: 10 * 60000,
    max: 40,
    message: "Demasiados intentos. Espera unos minutos."
});

const registerLimiter = createLimiter({
    windowMs: 60 * 60000,
    max: 5,
    message: "Demasiados registros desde esta conexion."
});

const usernameCheckLimiter = createLimiter({ windowMs: 60000, max: 30 });
const refreshLimiter = createLimiter({ windowMs: 60000, max: 10, keyFn: (req) => req.actor.id });
const pingLimiter = createLimiter({ windowMs: 60000, max: 120, keyFn: (req) => req.actor.id });
const mailSendLimiter = createLimiter({ windowMs: 60000, max: 10, keyFn: (req) => req.actor.id });
const mailPairLimiter = createLimiter({
    windowMs: 10 * 60000,
    max: 5,
    keyFn: (req) => `${req.actor.id}:${cleanId(req.body.toUserId)}`,
    message: "Demasiados mensajes a esta persona"
});
const friendsLimiter = createLimiter({ windowMs: 60000, max: 30, keyFn: (req) => req.actor.id });
const profileLimiter = createLimiter({ windowMs: 60 * 60000, max: 20, keyFn: (req) => req.actor.id });
const avatarLimiter = createLimiter({ windowMs: 60 * 60000, max: 8, keyFn: (req) => req.actor.id });
const bannerLimiter = createLimiter({ windowMs: 60 * 60000, max: 8, keyFn: (req) => req.actor.id });
const passwordLimiter = createLimiter({
    windowMs: 60 * 60000,
    max: 5,
    keyFn: (req) => req.actor.id,
    message: "Demasiados intentos. Espera un rato."
});
const blocksLimiter = createLimiter({ windowMs: 60000, max: 30, keyFn: (req) => req.actor.id });
const serviceLimiter = createLimiter({ windowMs: 60000, max: 600 });
const forumLimiter = createLimiter({ windowMs: 60000, max: 10, keyFn: (req) => req.actor.id });

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: !DB_SSL_INSECURE },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    statement_timeout: 15000
});

pool.on("error", (error) => {
    console.error("[MichuStudio] Pool error", error.message);
});

const USER_COLUMNS = `
    id, username, password_hash, account_key_hash, coins, inventory, friends,
    last_ping, is_playing, region, is_banned, ban_reason, token_valid_after,
    role, description, accent_color, created_at,
    status_text, hide_region, hide_online, badges, play_seconds, last_login,
    (avatar_webp IS NOT NULL) AS has_avatar,
    (banner_webp IS NOT NULL) AS has_banner
`;

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024, files: 1, fields: 5 },
    fileFilter(req, file, callback) {
        const allowed = ["image/jpeg", "image/png", "image/webp", "image/avif"];

        if (!allowed.includes(file.mimetype)) {
            return callback(new HttpError(400, "Formato de imagen no permitido"));
        }

        callback(null, true);
    }
});

const DUMMY_HASH = bcrypt.hashSync("michiverse-dummy-password", BCRYPT_ROUNDS);

function createToken(userId, originalAuthAt) {
    const iat = now();
    const oat = Number.isFinite(originalAuthAt) ? originalAuthAt : iat;
    const exp = Math.min(iat + TOKEN_TTL_MS, oat + MAX_SESSION_MS);

    const payload = {
        v: 1,
        u: String(userId),
        iat,
        oat,
        exp
    };

    const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = crypto.createHmac("sha256", TOKEN_SECRET).update(encoded).digest("base64url");

    return { token: `${encoded}.${signature}`, expiresAt: payload.exp, oat };
}

function verifyToken(token) {
    if (typeof token !== "string" || token.length < 10 || token.length > 512) {
        return null;
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
        return null;
    }

    const expected = crypto.createHmac("sha256", TOKEN_SECRET).update(parts[0]).digest("base64url");

    if (!safeEqual(parts[1], expected)) {
        return null;
    }

    let payload;

    try {
        payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    } catch {
        return null;
    }

    if (
        !payload ||
        payload.v !== 1 ||
        typeof payload.u !== "string" ||
        !Number.isFinite(payload.iat) ||
        !Number.isFinite(payload.exp)
    ) {
        return null;
    }

    const current = now();
    const oat = Number.isFinite(payload.oat) ? payload.oat : payload.iat;

    if (payload.exp <= current || payload.iat > current + 60000) {
        return null;
    }

    if (current - oat > MAX_SESSION_MS) {
        return null;
    }

    return { ...payload, oat };
}

function extractBearer(req) {
    const header = String(req.headers.authorization || "");

    if (header.length < 8 || header.slice(0, 7).toLowerCase() !== "bearer ") {
        return "";
    }

    return header.slice(7).trim();
}

async function loadUser(id) {
    if (!isValidUserId(id)) {
        return null;
    }

    const result = await pool.query(
        `SELECT ${USER_COLUMNS} FROM users WHERE id = $1 LIMIT 1`,
        [String(id)]
    );

    return result.rows[0] || null;
}

function findUserByUsername(username) {
    return pool.query(
        `SELECT ${USER_COLUMNS} FROM users WHERE lower(username) = lower($1) LIMIT 1`,
        [String(username || "").trim().slice(0, 64)]
    );
}

function tokenRevoked(payload, row) {
    const validAfter = row.token_valid_after ? new Date(row.token_valid_after).getTime() : 0;
    return payload.iat < validAfter;
}

async function ensureUserFields(row) {
    const sets = [];
    const values = [row.id];
    let accountKey = "";
    let accountKeyHash = "";

    function add(column, value, cast = "") {
        values.push(value);
        sets.push(`${column} = $${values.length}${cast}`);
    }

    if (row.coins === null || row.coins === undefined || !Number.isFinite(Number(row.coins))) {
        add("coins", 0);
    }

    if (!Array.isArray(row.inventory)) {
        add("inventory", "[]", "::jsonb");
    }

    if (!Array.isArray(row.friends)) {
        add("friends", "[]", "::jsonb");
    }

    if (row.region === null || row.region === undefined) {
        add("region", "");
    }

    if (!normalizeRole(row.role)) {
        add("role", DEFAULT_ROLE);
    }

    if (row.description === null || row.description === undefined) {
        add("description", "");
    }

    if (row.accent_color === null || row.accent_color === undefined) {
        add("accent_color", "");
    }

    if (row.status_text === null || row.status_text === undefined) {
        add("status_text", "");
    }

    if (row.hide_region === null || row.hide_region === undefined) {
        add("hide_region", false);
    }

    if (row.hide_online === null || row.hide_online === undefined) {
        add("hide_online", false);
    }

    if (!Array.isArray(row.badges)) {
        add("badges", "[]", "::jsonb");
    }

    if (row.play_seconds === null || row.play_seconds === undefined || !Number.isFinite(Number(row.play_seconds))) {
        add("play_seconds", 0);
    }

    if (row.is_banned === null || row.is_banned === undefined) {
        add("is_banned", false);
    }

    if (row.is_playing === null || row.is_playing === undefined) {
        add("is_playing", false);
    }

    if (!row.last_ping) {
        sets.push("last_ping = NOW()");
    }

    if (!row.account_key_hash) {
        accountKey = generateAccountKey();
        accountKeyHash = await bcrypt.hash(accountKey, ACCOUNT_KEY_ROUNDS);
        values.push(accountKeyHash);
        sets.push(`account_key_hash = COALESCE(account_key_hash, $${values.length})`);
    }

    if (sets.length === 0) {
        return { row, accountKey: "" };
    }

    const result = await pool.query(
        `UPDATE users SET ${sets.join(", ")} WHERE id = $1 RETURNING ${USER_COLUMNS}`,
        values
    );

    const updated = result.rows[0] || row;

    if (accountKey && String(updated.account_key_hash) !== accountKeyHash) {
        accountKey = "";
    }

    return { row: updated, accountKey };
}

async function authenticate(req, claimedUserId) {
    const token = extractBearer(req);

    if (token) {
        const payload = verifyToken(token);

        if (!payload) {
            return { error: 401, message: "Sesion invalida o expirada" };
        }

        const row = await loadUser(payload.u);

        if (!row) {
            return { error: 401, message: "Sesion invalida o expirada" };
        }

        if (tokenRevoked(payload, row)) {
            return { error: 401, message: "Sesion revocada" };
        }

        if (claimedUserId && String(claimedUserId) !== String(row.id)) {
            return { error: 403, message: "userId no coincide" };
        }

        return { row, viaToken: true, payload };
    }

    if (LEGACY_AUTH && claimedUserId) {
        const row = await loadUser(cleanId(claimedUserId));

        if (!row) {
            return { error: 404, message: "Usuario no encontrado" };
        }

        return { row, viaToken: false, payload: null };
    }

    return { error: 401, message: "Se requiere sesion" };
}

function requireAuth(claimFn) {
    return asyncHandler(async (req, res, next) => {
        const claimed = claimFn ? cleanId(claimFn(req)) : "";
        const result = await authenticate(req, claimed);

        if (result.error) {
            return res.status(result.error).json({ error: result.message });
        }

        if (result.row.is_banned) {
            return res.status(403).json({
                error: "Cuenta baneada",
                isBanned: true,
                banReason: result.row.ban_reason || ""
            });
        }

        req.actor = { id: String(result.row.id) };
        req.actorRow = result.row;
        req.actorViaToken = result.viaToken;
        req.tokenPayload = result.payload;

        next();
    });
}

function requireAuthLoose() {
    const strict = requireAuth(null);

    return (req, res, next) => {
        if (!extractBearer(req) && LEGACY_AUTH) {
            return next();
        }

        strict(req, res, next);
    };
}

const claimBody = (req) => req.body?.userId;
const claimParamId = (req) => req.params.id;
const claimParamUserId = (req) => req.params.userId;

function isOnlineMs(lastPing) {
    return typeof lastPing === "number" && now() - lastPing < ONLINE_WINDOW_MS;
}

function rowToUser(row) {
    if (!row) {
        return null;
    }

    const playSeconds = Number(row.play_seconds);

    return {
        id: String(row.id || ""),
        username: String(row.username || "Guest"),
        coins: Number.isFinite(Number(row.coins)) ? Number(row.coins) : 0,
        inventory: Array.isArray(row.inventory) ? row.inventory : [],
        friends: Array.isArray(row.friends) ? row.friends.map(String) : [],
        lastPing: row.last_ping ? new Date(row.last_ping).getTime() : 0,
        isPlaying: !!row.is_playing,
        region: String(row.region || ""),
        isBanned: !!row.is_banned,
        banReason: row.ban_reason ? String(row.ban_reason) : "",
        hasAvatar: !!row.has_avatar,
        hasBanner: !!row.has_banner,
        role: normalizeRole(row.role) || DEFAULT_ROLE,
        description: String(row.description || ""),
        accentColor: String(row.accent_color || ""),
        memberSince: row.created_at ? new Date(row.created_at).toISOString() : "",
        statusText: String(row.status_text || ""),
        hideRegion: !!row.hide_region,
        hideOnline: !!row.hide_online,
        badges: Array.isArray(row.badges) ? row.badges.map(String) : [],
        playSeconds: Number.isFinite(playSeconds) && playSeconds > 0 ? Math.floor(playSeconds) : 0,
        lastLogin: row.last_login ? new Date(row.last_login).toISOString() : ""
    };
}

function hoursFromSeconds(seconds) {
    return Math.floor(seconds / 360) / 10;
}

function getSelfUser(row) {
    const user = rowToUser(row);

    if (!user) {
        return null;
    }

    return {
        id: user.id,
        username: user.username,
        coins: user.coins,
        inventory: user.inventory,
        friends: user.friends,
        isPlaying: user.isPlaying,
        online: isOnlineMs(user.lastPing),
        region: user.region,
        isBanned: user.isBanned,
        profile_picture: user.hasAvatar ? `/users/${user.id}/avatar` : "",
        profile_banner: user.hasBanner ? `/users/${user.id}/banner` : "",
        role: user.role,
        description: user.description,
        accentColor: user.accentColor,
        memberSince: user.memberSince,
        statusText: user.statusText,
        badges: user.badges,
        hideRegion: user.hideRegion,
        hideOnline: user.hideOnline,
        playSeconds: user.playSeconds,
        hoursPlayed: hoursFromSeconds(user.playSeconds),
        lastLogin: user.lastLogin
    };
}

function getPublicProfile(row) {
    const user = rowToUser(row);

    if (!user) {
        return null;
    }

    const visible = !user.hideOnline;

    return {
        id: user.id,
        username: user.username,
        isPlaying: visible && user.isPlaying,
        online: visible && isOnlineMs(user.lastPing),
        region: user.hideRegion ? "" : user.region,
        isBanned: user.isBanned,
        profile_picture: user.hasAvatar ? `/users/${user.id}/avatar` : "",
        profile_banner: user.hasBanner ? `/users/${user.id}/banner` : "",
        role: user.role,
        description: user.description,
        accentColor: user.accentColor,
        memberSince: user.memberSince,
        statusText: user.statusText,
        badges: user.badges,
        hoursPlayed: hoursFromSeconds(user.playSeconds),
        lastLogin: visible ? user.lastLogin : ""
    };
}

function mapMail(mail) {
    return {
        id: String(mail.id),
        toUserId: String(mail.to_user_id),
        fromUserId: String(mail.from_user_id),
        type: String(mail.type),
        message: String(mail.message),
        createdAt: new Date(mail.created_at).toISOString(),
        isRead: !!mail.is_read
    };
}

async function insertMail(toUserId, fromUserId, type, message) {
    const result = await pool.query(
        `
        INSERT INTO mail (to_user_id, from_user_id, type, message)
        VALUES ($1, $2, $3, $4)
        RETURNING id, to_user_id, from_user_id, type, message, created_at, is_read
        `,
        [toUserId, fromUserId, type, message]
    );

    await pool.query(
        `
        DELETE FROM mail
        WHERE to_user_id = $1
          AND type = 'Normal'
          AND id NOT IN (
              SELECT id FROM mail
              WHERE to_user_id = $1
                AND type = 'Normal'
              ORDER BY created_at DESC, id DESC
              LIMIT $2
          )
        `,
        [toUserId, MAX_MAILS_PER_USER]
    );

    return result.rows[0];
}

async function isBlockedBetween(a, b) {
    const result = await pool.query(
        `SELECT 1 FROM blocks WHERE (user_id = $1 AND blocked_id = $2) OR (user_id = $2 AND blocked_id = $1) LIMIT 1`,
        [a, b]
    );

    return result.rows.length > 0;
}

async function initDb() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            coins INTEGER NOT NULL DEFAULT 0,
            inventory JSONB NOT NULL DEFAULT '[]'::jsonb,
            friends JSONB NOT NULL DEFAULT '[]'::jsonb,
            last_ping TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            is_playing BOOLEAN NOT NULL DEFAULT FALSE
        );
    `);

    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS region TEXT NOT NULL DEFAULT '';`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT FALSE;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_webp BYTEA;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS account_key_hash TEXT;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS token_valid_after TIMESTAMPTZ NOT NULL DEFAULT to_timestamp(0);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'User';`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS accent_color TEXT NOT NULL DEFAULT '';`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS banner_webp BYTEA;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status_text TEXT NOT NULL DEFAULT '';`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS hide_region BOOLEAN NOT NULL DEFAULT FALSE;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS hide_online BOOLEAN NOT NULL DEFAULT FALSE;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS badges JSONB NOT NULL DEFAULT '[]'::jsonb;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS play_seconds BIGINT NOT NULL DEFAULT 0;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;`);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS blocks (
            user_id TEXT NOT NULL,
            blocked_id TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (user_id, blocked_id)
        );
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks (blocked_id);`);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS friend_requests (
            from_user_id TEXT NOT NULL,
            to_user_id TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (from_user_id, to_user_id)
        );
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_friend_requests_to ON friend_requests (to_user_id, created_at DESC);`);

    try {
        await pool.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check') THEN
                    ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('Creator', 'User', 'Admin'));
                END IF;
            END $$;
        `);
    } catch (error) {
        console.error("[MichuStudio] No se pudo crear la restriccion de roles:", error.message);
    }

    await pool.query(`
        CREATE TABLE IF NOT EXISTS mail (
            id BIGSERIAL PRIMARY KEY,
            to_user_id TEXT NOT NULL,
            from_user_id TEXT NOT NULL,
            type TEXT NOT NULL CHECK (type IN ('Normal', 'Warning')),
            message TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            is_read BOOLEAN NOT NULL DEFAULT FALSE
        );
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_mail_to_user ON mail (to_user_id, created_at DESC);`);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS forum_posts (
            id BIGSERIAL PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_forum_posts_created ON forum_posts (created_at DESC, id DESC);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_forum_posts_user ON forum_posts (user_id, created_at DESC);`);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS forum_comments (
            id BIGSERIAL PRIMARY KEY,
            post_id BIGINT NOT NULL,
            user_id TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_forum_comments_post ON forum_comments (post_id, created_at ASC, id ASC);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_username_lower ON users (lower(username));`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_last_ping ON users (last_ping);`);

    try {
        await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower_unique ON users (lower(username));`);
    } catch (error) {
        console.error("[MichuStudio] No se pudo crear el indice unico de username:", error.message);
    }
}

async function repairAllUsers() {
    const statements = [
        `UPDATE users SET inventory = '[]'::jsonb WHERE inventory IS NULL OR jsonb_typeof(inventory) <> 'array'`,
        `UPDATE users SET friends = '[]'::jsonb WHERE friends IS NULL OR jsonb_typeof(friends) <> 'array'`,
        `UPDATE users SET coins = 0 WHERE coins IS NULL`,
        `UPDATE users SET region = '' WHERE region IS NULL`,
        `UPDATE users SET is_banned = FALSE WHERE is_banned IS NULL`,
        `UPDATE users SET is_playing = FALSE WHERE is_playing IS NULL`,
        `UPDATE users SET last_ping = to_timestamp(0) WHERE last_ping IS NULL`,
        `UPDATE users SET role = 'User' WHERE role IS NULL OR role NOT IN ('Creator', 'User', 'Admin')`,
        `UPDATE users SET description = '' WHERE description IS NULL`,
        `UPDATE users SET accent_color = '' WHERE accent_color IS NULL`,
        `UPDATE users SET status_text = '' WHERE status_text IS NULL`,
        `UPDATE users SET hide_region = FALSE WHERE hide_region IS NULL`,
        `UPDATE users SET hide_online = FALSE WHERE hide_online IS NULL`,
        `UPDATE users SET badges = '[]'::jsonb WHERE badges IS NULL OR jsonb_typeof(badges) <> 'array'`,
        `UPDATE users SET play_seconds = 0 WHERE play_seconds IS NULL OR play_seconds < 0`
    ];

    for (const sql of statements) {
        try {
            await pool.query(sql);
        } catch (error) {
            console.error("[MichuStudio] Repair error", error.message);
        }
    }
}

async function migrateAvatars() {
    const column = await pool.query(`
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'avatar_avif'
    `);

    if (column.rows.length === 0) {
        return;
    }

    let migrated = 0;

    for (;;) {
        const batch = await pool.query(`
            SELECT id, avatar_avif
            FROM users
            WHERE avatar_avif IS NOT NULL AND avatar_webp IS NULL
            LIMIT 20
        `);

        if (batch.rows.length === 0) {
            break;
        }

        for (const row of batch.rows) {
            try {
                const webp = await buildAvatarWebp(row.avatar_avif);

                await pool.query(
                    `UPDATE users SET avatar_webp = $2, avatar_avif = NULL WHERE id = $1`,
                    [row.id, webp]
                );

                migrated += 1;
            } catch (error) {
                console.error(`[MichuStudio] Avatar ilegible de ${row.id}, se descarta:`, error.message);

                await pool.query(`UPDATE users SET avatar_avif = NULL WHERE id = $1`, [row.id]);
            }
        }
    }

    await pool.query(`UPDATE users SET avatar_avif = NULL WHERE avatar_avif IS NOT NULL`);

    if (migrated > 0) {
        log("Avatares migrados a WebP", String(migrated));
    }
}

async function moderateContent({ text, imageBuffer, imageMime }) {
    const input = [];

    if (text !== undefined) {
        input.push({ type: "text", text: String(text) });
    }

    if (imageBuffer) {
        input.push({
            type: "image_url",
            image_url: {
                url: `data:${imageMime};base64,${imageBuffer.toString("base64")}`
            }
        });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    try {
        const response = await fetch("https://api.openai.com/v1/moderations", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify({ model: "omni-moderation-latest", input }),
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(`OpenAI Moderation ${response.status}`);
        }

        const data = await response.json();

        if (!data || !Array.isArray(data.results) || !data.results[0]) {
            throw new Error("Respuesta invalida de OpenAI Moderation");
        }

        return { flagged: !!data.results[0].flagged };
    } finally {
        clearTimeout(timeout);
    }
}

async function inspectImage(buffer) {
    let metadata;

    try {
        metadata = await sharp(buffer, { limitInputPixels: MAX_INPUT_PIXELS }).metadata();
    } catch {
        throw new HttpError(400, "Imagen invalida");
    }

    if (!metadata.width || !metadata.height || !metadata.format) {
        throw new HttpError(400, "No se pudo leer la imagen");
    }

    if (!["jpeg", "png", "webp", "avif"].includes(metadata.format)) {
        throw new HttpError(400, "Formato de imagen no compatible");
    }

    if (Number(metadata.pages || 1) > 1) {
        throw new HttpError(400, "No se permiten im\u00e1genes animadas");
    }

    return metadata;
}

function buildAvatarWebp(buffer) {
    return sharp(buffer, { limitInputPixels: MAX_INPUT_PIXELS })
        .rotate()
        .resize(AVATAR_SIZE, AVATAR_SIZE, { fit: "cover", position: "centre" })
        .flatten({ background: "#ffffff" })
        .webp({ quality: 80, effort: 4 })
        .toBuffer();
}

function buildModerationJpeg(buffer) {
    return sharp(buffer, { limitInputPixels: MAX_INPUT_PIXELS })
        .rotate()
        .resize(512, 512, { fit: "cover", position: "centre" })
        .flatten({ background: "#ffffff" })
        .jpeg({ quality: 80 })
        .toBuffer();
}

function buildBannerWebp(buffer) {
    return sharp(buffer, { limitInputPixels: MAX_INPUT_PIXELS })
        .rotate()
        .resize(BANNER_WIDTH, BANNER_HEIGHT, { fit: "cover", position: "centre" })
        .flatten({ background: "#ffffff" })
        .webp({ quality: 80, effort: 4 })
        .toBuffer();
}

function buildBannerModerationJpeg(buffer) {
    return sharp(buffer, { limitInputPixels: MAX_INPUT_PIXELS })
        .rotate()
        .resize(768, 768, { fit: "inside", withoutEnlargement: true })
        .flatten({ background: "#ffffff" })
        .jpeg({ quality: 80 })
        .toBuffer();
}

async function validateNewUsername(username, currentUserId) {
    if (username.length < 3) {
        return { status: 400, error: "Username muy corto" };
    }

    if (username.length > 32) {
        return { status: 400, error: "Username muy largo" };
    }

    if (!USERNAME_REGEX.test(username) || / {2,}/.test(username)) {
        return { status: 400, error: "El nombre contiene caracteres no permitidos" };
    }

    if (moderateUsernameLocally(username).blocked) {
        log("Username blocked locally", username);
        return { status: 400, error: "Ese nombre no est\u00e1 permitido" };
    }

    const existing = await findUserByUsername(username);

    if (existing.rows.length > 0 && String(existing.rows[0].id) !== String(currentUserId || "")) {
        return { status: 409, error: "Ese nombre ya existe" };
    }

    let moderation;

    try {
        moderation = await moderateContent({ text: username });
    } catch (error) {
        console.error("[MichuStudio] Moderation error", error.message);
        return { status: 503, error: "No se pudo comprobar el nombre" };
    }

    if (moderation.flagged) {
        return { status: 400, error: "Ese nombre no est\u00e1 permitido" };
    }

    return null;
}

const ADMIN_SESSION_TTL = 30 * 60 * 1000;
const ADMIN_SESSION_COOKIE = "mv_admin_session";
const ADMIN_BLOCK_MS = 10 * 60 * 1000;
const adminSessions = new Map();
const adminLoginAttempts = new Map();

function parseCookies(req) {
    const header = String(req.headers.cookie || "");
    const cookies = {};

    for (const part of header.split(";")) {
        const index = part.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();

        try {
            cookies[key] = decodeURIComponent(value);
        } catch {
            cookies[key] = "";
        }
    }

    return cookies;
}

function isAdminBlocked(ip) {
    const entry = adminLoginAttempts.get(ip);
    return !!entry && entry.blockedUntil > now();
}

function registerAdminFailure(ip) {
    const current = now();
    let entry = adminLoginAttempts.get(ip);

    if (
        !entry ||
        entry.resetAt <= current ||
        (entry.blockedUntil && entry.blockedUntil <= current)
    ) {
        entry = { failures: 0, resetAt: current + ADMIN_BLOCK_MS, blockedUntil: 0 };
    }

    entry.failures += 1;

    if (entry.failures >= 5) {
        entry.blockedUntil = current + ADMIN_BLOCK_MS;
        entry.resetAt = entry.blockedUntil;
    }

    adminLoginAttempts.set(ip, entry);
}

function isSameOrigin(req) {
    const origin = req.get("origin");
    const expected = `${req.protocol}://${req.get("host")}`;
    const readOnly = req.method === "GET" || req.method === "HEAD";

    if (!origin) {
        return readOnly;
    }

    return origin === expected;
}

function createAdminSession() {
    if (adminSessions.size >= MAX_ADMIN_SESSIONS) {
        const oldest = adminSessions.keys().next().value;
        adminSessions.delete(oldest);
    }

    const token = crypto.randomBytes(32).toString("hex");

    adminSessions.set(token, {
        createdAt: now(),
        expiresAt: now() + ADMIN_SESSION_TTL
    });

    return token;
}

function getAdminSession(req) {
    const token = parseCookies(req)[ADMIN_SESSION_COOKIE];

    if (!token) {
        return null;
    }

    const session = adminSessions.get(token);

    if (!session) {
        return null;
    }

    if (session.expiresAt <= now()) {
        adminSessions.delete(token);
        return null;
    }

    session.expiresAt = now() + ADMIN_SESSION_TTL;

    return { token, session };
}

function setAdminCookie(res, token, maxAgeSeconds) {
    res.setHeader(
        "Set-Cookie",
        `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}; Max-Age=${maxAgeSeconds}; Path=/admin; HttpOnly; Secure; SameSite=Strict`
    );
}

function clearAdminCookie(res) {
    res.setHeader(
        "Set-Cookie",
        `${ADMIN_SESSION_COOKIE}=; Max-Age=0; Path=/admin; HttpOnly; Secure; SameSite=Strict`
    );
}

setInterval(() => {
    const current = now();

    for (const [token, session] of adminSessions.entries()) {
        if (session.expiresAt <= current) {
            adminSessions.delete(token);
        }
    }

    for (const [ip, entry] of adminLoginAttempts.entries()) {
        if (entry.resetAt <= current && entry.blockedUntil <= current) {
            adminLoginAttempts.delete(ip);
        }
    }
}, 60000).unref();

function requireAdmin(req, res) {
    res.setHeader("Cache-Control", "no-store");

    if (!isSameOrigin(req)) {
        res.status(403).json({ error: "Origen no permitido" });
        return false;
    }

    const session = getAdminSession(req);

    if (session) {
        req.adminSession = session;
        return true;
    }

    if (ALLOW_ADMIN_KEY_HEADER) {
        if (isAdminBlocked(req.ip)) {
            res.status(429).json({ error: "Demasiados intentos" });
            return false;
        }

        const supplied = String(req.headers["x-admin-key"] || "");

        if (supplied && safeEqual(supplied, ADMIN_KEY)) {
            return true;
        }

        if (supplied) {
            registerAdminFailure(req.ip);
        }
    }

    res.status(401).json({ error: "No autorizado" });
    return false;
}

function adminGuard(req, res, next) {
    if (requireAdmin(req, res)) {
        next();
    }
}

async function banUser(userId, reason) {
    const result = await pool.query(
        `
        UPDATE users
        SET is_banned = TRUE,
            ban_reason = $2,
            last_ping = to_timestamp(0),
            is_playing = FALSE,
            token_valid_after = $3::timestamptz
        WHERE id = $1
        RETURNING id, username, is_banned, ban_reason
        `,
        [userId, reason, new Date()]
    );

    return result.rows[0] || null;
}

async function unbanUser(userId) {
    const result = await pool.query(
        `
        UPDATE users
        SET is_banned = FALSE, ban_reason = NULL
        WHERE id = $1
        RETURNING id, username, is_banned
        `,
        [userId]
    );

    return result.rows[0] || null;
}

async function updateFriendship(userId, friendId, add) {
    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        const locked = await client.query(
            `SELECT ${USER_COLUMNS} FROM users WHERE id = ANY($1::text[]) ORDER BY id FOR UPDATE`,
            [[userId, friendId]]
        );

        const userRow = locked.rows.find((row) => String(row.id) === userId);
        const friendRow = locked.rows.find((row) => String(row.id) === friendId);

        if (!userRow) {
            await client.query("ROLLBACK");
            return { status: 404, error: "Usuario no encontrado" };
        }

        if (add && !friendRow) {
            await client.query("ROLLBACK");
            return { status: 404, error: "Usuario no encontrado" };
        }

        if (add && friendRow.is_banned) {
            await client.query("ROLLBACK");
            return { status: 403, error: "No se puede modificar la amistad" };
        }

        const userFriends = Array.isArray(userRow.friends) ? userRow.friends.map(String) : [];
        const friendFriends = friendRow && Array.isArray(friendRow.friends) ? friendRow.friends.map(String) : [];

        let nextUserFriends;
        let nextFriendFriends;

        if (add) {
            if (!userFriends.includes(friendId) && userFriends.length >= MAX_FRIENDS) {
                await client.query("ROLLBACK");
                return { status: 400, error: "Limite de amigos alcanzado" };
            }

            if (!friendFriends.includes(userId) && friendFriends.length >= MAX_FRIENDS) {
                await client.query("ROLLBACK");
                return { status: 400, error: "Esa persona alcanzo su limite de amigos" };
            }

            nextUserFriends = userFriends.includes(friendId) ? userFriends : [...userFriends, friendId];
            nextFriendFriends = friendFriends.includes(userId) ? friendFriends : [...friendFriends, userId];
        } else {
            nextUserFriends = userFriends.filter((id) => id !== friendId);
            nextFriendFriends = friendFriends.filter((id) => id !== userId);
        }

        const updatedUser = await client.query(
            `UPDATE users SET friends = $1::jsonb WHERE id = $2 RETURNING ${USER_COLUMNS}`,
            [JSON.stringify(nextUserFriends), userId]
        );

        let updatedFriend = null;

        if (friendRow) {
            const result = await client.query(
                `UPDATE users SET friends = $1::jsonb WHERE id = $2 RETURNING ${USER_COLUMNS}`,
                [JSON.stringify(nextFriendFriends), friendId]
            );

            updatedFriend = result.rows[0];
        }

        await client.query("COMMIT");

        return {
            status: 200,
            user: updatedUser.rows[0],
            friend: updatedFriend,
            userName: userRow.username,
            friendName: friendRow ? friendRow.username : friendId
        };
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
    } finally {
        client.release();
    }
}

async function acceptFriendship(userId, friendId) {
    const result = await updateFriendship(userId, friendId, true);

    if (result.status === 200) {
        await pool.query(
            `DELETE FROM friend_requests WHERE (from_user_id = $1 AND to_user_id = $2) OR (from_user_id = $2 AND to_user_id = $1)`,
            [userId, friendId]
        );
    }

    return result;
}

const app = express();

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-site");
    res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    res.setHeader("Cache-Control", "no-store");
    next();
});

app.use((req, res, next) => {
    const origin = req.headers.origin;

    if (origin && CORS_ORIGINS.includes(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Vary", "Origin");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
        res.setHeader("Access-Control-Max-Age", "600");

        if (req.method === "OPTIONS") {
            return res.status(204).end();
        }
    }

    next();
});

app.use(globalLimiter);
app.use(express.json({ limit: "16kb", strict: true }));

app.use((req, res, next) => {
    if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
        req.body = {};
    }

    next();
});

app.use(express.static(path.join(__dirname, "public"), { index: false, dotfiles: "deny" }));
app.use("/games", express.static(path.join(__dirname, "games"), { index: false, dotfiles: "deny" }));
app.get("/Juegos.json", (req, res) => {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.sendFile(path.join(__dirname, "Juegos.json"), { dotfiles: "deny" });
});

app.get("/", (req, res) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
    res.sendFile(path.join(__dirname, "public", "index.html"), { dotfiles: "deny" });
});

app.get("/health", (req, res) => {
    res.json({ ok: true });
});

app.get("/admin", (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    );

    res.sendFile(path.join(__dirname, "admin.html"), { dotfiles: "deny" });
});

app.post("/admin/login", asyncHandler(async (req, res) => {
    if (!isSameOrigin(req)) {
        return res.status(403).json({ error: "Origen no permitido" });
    }

    const ip = req.ip;

    if (isAdminBlocked(ip)) {
        const entry = adminLoginAttempts.get(ip);
        const seconds = Math.ceil((entry.blockedUntil - now()) / 1000);
        return res.status(429).json({ error: `Demasiados intentos. Espera ${seconds} segundos.` });
    }

    const password = String(req.body.password || "").slice(0, 256);

    if (!safeEqual(password, ADMIN_KEY)) {
        registerAdminFailure(ip);
        return res.status(401).json({ error: "Contrase\u00f1a incorrecta" });
    }

    adminLoginAttempts.delete(ip);

    const oldSession = getAdminSession(req);

    if (oldSession) {
        adminSessions.delete(oldSession.token);
    }

    setAdminCookie(res, createAdminSession(), Math.floor(ADMIN_SESSION_TTL / 1000));

    log("Admin login", ip);

    res.json({ ok: true });
}));

app.get("/admin/session", adminGuard, (req, res) => {
    res.json({ ok: true });
});

app.post("/admin/logout", (req, res) => {
    if (!isSameOrigin(req)) {
        return res.status(403).json({ error: "Origen no permitido" });
    }

    const session = getAdminSession(req);

    if (session) {
        adminSessions.delete(session.token);
    }

    clearAdminCookie(res);
    res.json({ ok: true });
});

app.get("/admin/users", adminGuard, asyncHandler(async (req, res) => {
    const result = await pool.query(`
        SELECT id, username, coins, region, last_ping, is_playing, is_banned, ban_reason, role,
               (avatar_webp IS NOT NULL) AS has_avatar,
               (banner_webp IS NOT NULL) AS has_banner
        FROM users
        ORDER BY lower(username) ASC, id ASC
    `);

    const users = result.rows.map((row) => {
        const lastPing = row.last_ping ? new Date(row.last_ping).getTime() : 0;

        return {
            id: String(row.id),
            username: String(row.username),
            coins: Number(row.coins || 0),
            region: String(row.region || ""),
            is_playing: !!row.is_playing,
            online: isOnlineMs(lastPing),
            is_banned: !!row.is_banned,
            ban_reason: String(row.ban_reason || ""),
            has_avatar: !!row.has_avatar,
            has_banner: !!row.has_banner,
            role: normalizeRole(row.role) || DEFAULT_ROLE
        };
    });

    res.json({ ok: true, users });
}));

app.delete("/admin/users/:id", adminGuard, asyncHandler(async (req, res) => {
    const userId = cleanId(req.params.id);

    if (!isValidUserId(userId)) {
        return res.status(400).json({ error: "Falta userId" });
    }

    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        const userResult = await client.query(
            `SELECT id, username FROM users WHERE id = $1 LIMIT 1`,
            [userId]
        );

        if (userResult.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        const deletedUser = userResult.rows[0];

        await client.query(
            `
            UPDATE users
            SET friends = COALESCE(
                (
                    SELECT jsonb_agg(to_jsonb(friend_id))
                    FROM jsonb_array_elements_text(
                        CASE WHEN jsonb_typeof(friends) = 'array' THEN friends ELSE '[]'::jsonb END
                    ) AS f(friend_id)
                    WHERE friend_id <> $1::text
                ),
                '[]'::jsonb
            )
            WHERE id <> $1::text
              AND jsonb_typeof(friends) = 'array'
              AND friends @> jsonb_build_array($1::text)
            `,
            [userId]
        );

        await client.query(
            `DELETE FROM mail WHERE to_user_id = $1 OR from_user_id = $1`,
            [userId]
        );

        await client.query(
            `DELETE FROM forum_comments WHERE post_id IN (SELECT id FROM forum_posts WHERE user_id = $1) OR user_id = $1`,
            [userId]
        );
        await client.query(`DELETE FROM forum_posts WHERE user_id = $1`, [userId]);

        await client.query(
            `DELETE FROM blocks WHERE user_id = $1 OR blocked_id = $1`,
            [userId]
        );

        await client.query(
            `DELETE FROM friend_requests WHERE from_user_id = $1 OR to_user_id = $1`,
            [userId]
        );

        await client.query(`DELETE FROM users WHERE id = $1`, [userId]);

        await client.query("COMMIT");

        log("Admin deleted user", `${deletedUser.username} (${deletedUser.id})`);

        res.json({
            ok: true,
            deleted_user: {
                id: String(deletedUser.id),
                username: String(deletedUser.username)
            }
        });
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
    } finally {
        client.release();
    }
}));

app.post("/admin/users/:id/ban", adminGuard, asyncHandler(async (req, res) => {
    const userId = cleanId(req.params.id);
    const reason = cleanText(req.body.reason, 500) || "Baneado por administraci\u00f3n";

    if (!isValidUserId(userId)) {
        return res.status(400).json({ error: "Falta userId" });
    }

    const row = await banUser(userId, reason);

    if (!row) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    log("Admin banned user", `${row.username} (${userId})`);

    res.json({
        ok: true,
        user: {
            id: String(row.id),
            username: String(row.username),
            is_banned: !!row.is_banned,
            ban_reason: String(row.ban_reason || "")
        }
    });
}));

app.post("/admin/users/:id/unban", adminGuard, asyncHandler(async (req, res) => {
    const userId = cleanId(req.params.id);

    if (!isValidUserId(userId)) {
        return res.status(400).json({ error: "Falta userId" });
    }

    const row = await unbanUser(userId);

    if (!row) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    log("Admin unbanned user", `${row.username} (${userId})`);

    res.json({
        ok: true,
        user: {
            id: String(row.id),
            username: String(row.username),
            is_banned: !!row.is_banned
        }
    });
}));

app.post("/admin/users/:id/role", adminGuard, asyncHandler(async (req, res) => {
    const userId = cleanId(req.params.id);
    const role = normalizeRole(req.body.role);

    if (!isValidUserId(userId) || !role) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const result = await pool.query(
        `UPDATE users SET role = $2 WHERE id = $1 RETURNING id, username, role`,
        [userId, role]
    );

    const row = result.rows[0];

    if (!row) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    log("Admin changed role", `${row.username} (${userId}) -> ${row.role}`);

    res.json({
        ok: true,
        user: {
            id: String(row.id),
            username: String(row.username),
            role: String(row.role)
        }
    });
}));

app.post("/admin/users/:id/username", adminGuard, asyncHandler(async (req, res) => {
    const userId = cleanId(req.params.id);
    const username = cleanUsername(req.body.username);

    if (!isValidUserId(userId) || !username) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const usernameError = await validateNewUsername(username, userId);

    if (usernameError) {
        return res.status(usernameError.status).json({ error: usernameError.error });
    }

    try {
        const result = await pool.query(
            `UPDATE users SET username = $2 WHERE id = $1 RETURNING id, username`,
            [userId, username]
        );

        const row = result.rows[0];

        if (!row) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        log("Admin changed username", `${row.username} (${userId})`);
        res.json({ ok: true, user: { id: String(row.id), username: String(row.username) } });
    } catch (error) {
        if (error && error.code === "23505") {
            return res.status(409).json({ error: "Ese nombre ya existe" });
        }
        throw error;
    }
}));

app.post("/admin/users/:id/reset-profile", adminGuard, asyncHandler(async (req, res) => {
    const userId = cleanId(req.params.id);

    if (!isValidUserId(userId)) {
        return res.status(400).json({ error: "Falta userId" });
    }

    const result = await pool.query(
        `UPDATE users SET description = '', status_text = '', accent_color = '', banner_webp = NULL WHERE id = $1 RETURNING id, username`,
        [userId]
    );

    const row = result.rows[0];

    if (!row) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    log("Admin reset profile", `${row.username} (${userId})`);

    res.json({ ok: true });
}));

app.post("/admin/users/:id/badges", adminGuard, asyncHandler(async (req, res) => {
    const userId = cleanId(req.params.id);
    const input = Array.isArray(req.body.badges) ? req.body.badges : null;

    if (!isValidUserId(userId) || !input) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const badges = [...new Set(input.map((item) => String(item || "").trim().toLowerCase()))];

    if (badges.length > MAX_BADGES || badges.some((item) => !BADGE_REGEX.test(item))) {
        return res.status(400).json({ error: "Insignias invalidas" });
    }

    const result = await pool.query(
        `UPDATE users SET badges = $2::jsonb WHERE id = $1 RETURNING id, username, badges`,
        [userId, JSON.stringify(badges)]
    );

    const row = result.rows[0];

    if (!row) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    log("Admin set badges", `${row.username} (${userId})`);

    res.json({ ok: true, user: { id: String(row.id), username: String(row.username), badges } });
}));

app.post("/admin/users/:id/email", adminGuard, asyncHandler(async (req, res) => {
    const userId = cleanId(req.params.id);
    const message = cleanText(req.body.message, 2000);

    if (!isValidUserId(userId) || !message) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const receiver = await loadUser(userId);

    if (!receiver) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const mail = await insertMail(userId, "ADMIN", "Normal", message);

    log("Admin sent mail", `${receiver.username} (${receiver.id})`);

    res.json({
        ok: true,
        mailId: String(mail.id),
        createdAt: new Date(mail.created_at).toISOString()
    });
}));

app.post("/admin/mail", adminGuard, asyncHandler(async (req, res) => {
    const fromUserId = cleanId(req.body.fromUserId);
    const toUserId = cleanId(req.body.toUserId);
    const type = normalizeMailType(req.body.type);
    const message = cleanText(req.body.message, 2000);

    if (!isValidUserId(fromUserId) || !isValidUserId(toUserId) || !type || !message) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const sender = await loadUser(fromUserId);
    const receiver = await loadUser(toUserId);

    if (!sender || !receiver) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const mail = await insertMail(toUserId, fromUserId, type, message);

    res.json({ ok: true, mailId: String(mail.id) });
}));

app.post("/admin/ban", adminGuard, asyncHandler(async (req, res) => {
    const userId = cleanId(req.body.userId);
    const reason = cleanText(req.body.reason, 500) || "Sin motivo";

    if (!isValidUserId(userId)) {
        return res.status(400).json({ error: "Falta userId" });
    }

    const row = await banUser(userId, reason);

    if (!row) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    log("User banned", `${row.username} (${userId})`);

    res.json({
        ok: true,
        user: {
            id: String(row.id),
            username: String(row.username),
            isBanned: !!row.is_banned,
            banReason: String(row.ban_reason || "")
        }
    });
}));

app.post("/admin/unban", adminGuard, asyncHandler(async (req, res) => {
    const userId = cleanId(req.body.userId);

    if (!isValidUserId(userId)) {
        return res.status(400).json({ error: "Falta userId" });
    }

    const row = await unbanUser(userId);

    if (!row) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    log("User unbanned", `${row.username} (${userId})`);

    res.json({
        ok: true,
        user: {
            id: String(row.id),
            username: String(row.username),
            isBanned: !!row.is_banned
        }
    });
}));

app.post("/register", registerLimiter, asyncHandler(async (req, res) => {
    const username = cleanUsername(req.body.username);
    const password = String(req.body.password || "");
    const region = normalizeRegion(req.body.region);

    if (!username || !password) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const passwordError = validatePassword(password);

    if (passwordError) {
        return res.status(400).json({ error: passwordError });
    }

    if (region && !isValidRegion(region)) {
        return res.status(400).json({ error: "La regi\u00f3n debe usar 2 letras" });
    }

    const usernameError = await validateNewUsername(username, "");

    if (usernameError) {
        return res.status(usernameError.status).json({ error: usernameError.error });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const accountKey = generateAccountKey();
    const accountKeyHash = await bcrypt.hash(accountKey, ACCOUNT_KEY_ROUNDS);

    let inserted = null;

    for (let attempts = 0; attempts < 10; attempts++) {
        const id = generateUniqueId();

        try {
            const result = await pool.query(
                `
                INSERT INTO users (
                    id, username, password_hash, coins, inventory, friends,
                    last_ping, is_playing, region, is_banned, ban_reason,
                    avatar_webp, account_key_hash, role, created_at, last_login
                )
                VALUES ($1, $2, $3, 0, '[]'::jsonb, '[]'::jsonb, NOW(), FALSE, $4, FALSE, NULL, NULL, $5, 'User', NOW(), NOW())
                RETURNING ${USER_COLUMNS}
                `,
                [id, username, passwordHash, region, accountKeyHash]
            );

            inserted = result.rows[0];
            break;
        } catch (error) {
            if (error && error.code === "23505") {
                if (String(error.constraint || "").includes("pkey")) {
                    continue;
                }

                return res.status(409).json({ error: "Ese nombre ya existe" });
            }

            throw error;
        }
    }

    if (!inserted) {
        return res.status(500).json({ error: "No se pudo crear el usuario" });
    }

    log("User registered", `${username} (${inserted.id})`);

    const session = createToken(inserted.id);

    res.json({
        ok: true,
        user: getSelfUser(inserted),
        accountKey,
        accountKeyGenerated: true,
        token: session.token,
        tokenExpiresAt: session.expiresAt
    });
}));

app.post("/login", loginIpLimiter, loginLimiter, asyncHandler(async (req, res) => {
    const username = cleanUsername(req.body.username);
    const password = String(req.body.password || "");

    if (!username || !password || password.length > 256) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const result = await findUserByUsername(username);
    const row = result.rows[0] || null;

    const passwordOk = await bcrypt.compare(
        password,
        row ? String(row.password_hash || DUMMY_HASH) : DUMMY_HASH
    );

    if (!row || !passwordOk) {
        return res.status(401).json({ error: "Usuario o contrase\u00f1a incorrectos" });
    }

    if (row.is_banned) {
        return res.status(403).json({
            error: "Cuenta baneada",
            isBanned: true,
            banReason: row.ban_reason || ""
        });
    }

    try {
        if (bcrypt.getRounds(String(row.password_hash)) < BCRYPT_ROUNDS) {
            const upgraded = await bcrypt.hash(password, BCRYPT_ROUNDS);

            await pool.query(`UPDATE users SET password_hash = $2 WHERE id = $1`, [row.id, upgraded]);
        }
    } catch (error) {
        console.error("[MichuStudio] Rehash error", error.message);
    }

    const ensured = await ensureUserFields(row);

    const updated = await pool.query(
        `UPDATE users SET last_ping = NOW(), last_login = NOW() WHERE id = $1 RETURNING ${USER_COLUMNS}`,
        [row.id]
    );

    log("User logged", `${row.username} (${row.id})`);

    const session = createToken(row.id);

    const response = {
        ok: true,
        user: getSelfUser(updated.rows[0] || ensured.row),
        token: session.token,
        tokenExpiresAt: session.expiresAt
    };

    if (ensured.accountKey) {
        response.accountKey = ensured.accountKey;
        response.accountKeyGenerated = true;
    }

    res.json(response);
}));

app.get("/auth/me", requireAuth(null), asyncHandler(async (req, res) => {
    const ensured = await ensureUserFields(req.actorRow);

    const response = { ok: true, user: getSelfUser(ensured.row) };

    if (ensured.accountKey) {
        response.accountKey = ensured.accountKey;
        response.accountKeyGenerated = true;
    }

    res.json(response);
}));

app.post("/auth/refresh", requireAuth(null), refreshLimiter, (req, res) => {
    if (!req.tokenPayload) {
        return res.status(400).json({ error: "Se requiere sesion" });
    }

    const session = createToken(req.actor.id, req.tokenPayload.oat);

    res.json({ ok: true, token: session.token, tokenExpiresAt: session.expiresAt });
});

if (SERVICE_KEY) {
    app.post("/auth/verify", serviceLimiter, asyncHandler(async (req, res) => {
        if (!safeEqual(String(req.headers["x-service-key"] || ""), SERVICE_KEY)) {
            return res.status(404).json({ error: "Endpoint no encontrado" });
        }

        const payload = verifyToken(String(req.body.token || ""));

        if (!payload) {
            return res.json({ ok: false });
        }

        const row = await loadUser(payload.u);

        if (!row || tokenRevoked(payload, row)) {
            return res.json({ ok: false });
        }

        if (row.is_banned) {
            return res.json({ ok: false, isBanned: true });
        }

        res.json({
            ok: true,
            userId: String(row.id),
            username: String(row.username),
            isBanned: false
        });
    }));
}

app.post("/logout", requireAuth(claimBody), asyncHandler(async (req, res) => {
    const revoke = req.body.revokeTokens === true;

    await pool.query(
        `
        UPDATE users
        SET last_ping = to_timestamp(0),
            is_playing = FALSE,
            token_valid_after = CASE WHEN $2::boolean THEN $3::timestamptz ELSE token_valid_after END
        WHERE id = $1
        `,
        [req.actor.id, revoke, new Date()]
    );

    log("User logged out", `${req.actorRow.username} (${req.actor.id})`);

    res.json({ ok: true });
}));

app.post("/ping", requireAuth(claimBody), pingLimiter, asyncHandler(async (req, res) => {
    const isPlaying = req.body.isPlaying === true;

    const updated = await pool.query(
        `
        UPDATE users
        SET play_seconds = play_seconds + CASE
                WHEN is_playing AND last_ping > NOW() - INTERVAL '30 seconds'
                THEN FLOOR(LEAST(EXTRACT(EPOCH FROM (NOW() - last_ping)), 30))::bigint
                ELSE 0
            END,
            last_ping = NOW(),
            is_playing = $2
        WHERE id = $1
        RETURNING is_playing
        `,
        [req.actor.id, isPlaying]
    );

    res.json({
        ok: true,
        online: true,
        isPlaying: updated.rows[0].is_playing
    });
}));

app.get("/users", requireAuthLoose(), asyncHandler(async (req, res) => {
    const query = cleanText(req.query.q, 32).replace(/[\\%_]/g, "\\$&");
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), 200);

    const result = await pool.query(
        `
        SELECT ${USER_COLUMNS}
        FROM users
        WHERE ($1::text = '' OR lower(username) LIKE lower($1::text) || '%')
        ORDER BY lower(username) ASC
        LIMIT $2
        `,
        [query, limit]
    );

    res.json({ ok: true, users: result.rows.map(getPublicProfile) });
}));

app.get("/online", requireAuthLoose(), asyncHandler(async (req, res) => {
    const result = await pool.query(
        `
        SELECT ${USER_COLUMNS}
        FROM users
        WHERE last_ping > NOW() - ($1::int * INTERVAL '1 millisecond')
          AND hide_online = FALSE
        ORDER BY lower(username) ASC
        LIMIT 200
        `,
        [ONLINE_WINDOW_MS]
    );

    res.json({ ok: true, users: result.rows.map(getPublicProfile) });
}));

app.get("/users/:id", asyncHandler(async (req, res) => {
    const row = await loadUser(cleanId(req.params.id));

    if (!row) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const payload = verifyToken(extractBearer(req));

    const isSelf =
        !!payload &&
        payload.u === String(row.id) &&
        !tokenRevoked(payload, row) &&
        !row.is_banned;

    res.json({ ok: true, user: isSelf ? getSelfUser(row) : getPublicProfile(row) });
}));

app.get("/users/:id/avatar", asyncHandler(async (req, res) => {
    const id = cleanId(req.params.id);

    if (!isValidUserId(id)) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const result = await pool.query(
        `SELECT avatar_webp FROM users WHERE id = $1 LIMIT 1`,
        [id]
    );

    if (result.rows.length === 0) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const avatar = result.rows[0].avatar_webp;

    if (!avatar) {
        return res.status(404).json({ error: "Este usuario no tiene foto de perfil" });
    }

    res.setHeader("Content-Type", "image/webp");
    res.setHeader("Cache-Control", "public, max-age=300");
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");

    res.send(avatar);
}));

app.get("/users/:id/banner", asyncHandler(async (req, res) => {
    const id = cleanId(req.params.id);

    if (!isValidUserId(id)) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const result = await pool.query(
        `SELECT banner_webp FROM users WHERE id = $1 LIMIT 1`,
        [id]
    );

    if (result.rows.length === 0) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const banner = result.rows[0].banner_webp;

    if (!banner) {
        return res.status(404).json({ error: "Este usuario no tiene banner" });
    }

    res.setHeader("Content-Type", "image/webp");
    res.setHeader("Cache-Control", "public, max-age=300");
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");

    res.send(banner);
}));

app.get("/username-exists/:username", usernameCheckLimiter, asyncHandler(async (req, res) => {
    const username = cleanUsername(req.params.username);

    if (!username) {
        return res.status(400).json({ error: "Falta username" });
    }

    const result = await findUserByUsername(username);

    res.json({ ok: true, exists: result.rows.length > 0 });
}));

app.get("/presence/:id", asyncHandler(async (req, res) => {
    const row = await loadUser(cleanId(req.params.id));

    if (!row) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = rowToUser(row);

    res.json({
        ok: true,
        userId: user.id,
        username: user.username,
        online: !user.hideOnline && isOnlineMs(user.lastPing),
        isPlaying: !user.hideOnline && user.isPlaying,
        region: user.hideRegion ? "" : user.region
    });
}));

app.post("/profile/update", requireAuth(claimBody), profileLimiter, asyncHandler(async (req, res) => {
    const user = req.actorRow;
    const userId = req.actor.id;

    const newUsername = req.body.username !== undefined ? cleanUsername(req.body.username) : null;
    const newRegion = req.body.region !== undefined ? normalizeRegion(req.body.region) : null;
    const newDescription = req.body.description !== undefined ? cleanDescription(req.body.description) : null;
    const newAccent = req.body.accentColor !== undefined ? String(req.body.accentColor || "").trim().toUpperCase() : null;
    const newStatus = req.body.statusText !== undefined ? cleanStatus(req.body.statusText) : null;
    const newHideRegion = typeof req.body.hideRegion === "boolean" ? req.body.hideRegion : null;
    const newHideOnline = typeof req.body.hideOnline === "boolean" ? req.body.hideOnline : null;

    let username = user.username;

    if (newUsername !== null && newUsername !== user.username) {
        const usernameError = await validateNewUsername(newUsername, userId);

        if (usernameError) {
            return res.status(usernameError.status).json({ error: usernameError.error });
        }

        username = newUsername;
    }

    let region = user.region || "";

    if (newRegion !== null) {
        if (newRegion !== "" && !isValidRegion(newRegion)) {
            return res.status(400).json({ error: "La regi\u00f3n debe usar 2 letras" });
        }

        region = newRegion;
    }

    let description = user.description || "";
    let statusText = user.status_text || "";
    const textsToCheck = [];

    if (newDescription !== null && newDescription !== description) {
        description = newDescription;

        if (description !== "") {
            textsToCheck.push(description);
        }
    }

    if (newStatus !== null && newStatus !== statusText) {
        statusText = newStatus;

        if (statusText !== "") {
            textsToCheck.push(statusText);
        }
    }

    if (textsToCheck.length > 0) {
        let moderation;

        try {
            moderation = await moderateContent({ text: textsToCheck.join("\n") });
        } catch (error) {
            console.error("[MichuStudio] Moderation error", error.message);
            return res.status(503).json({ error: "No se pudo comprobar el texto" });
        }

        if (moderation.flagged) {
            return res.status(400).json({ error: "El texto no est\u00e1 permitido" });
        }
    }

    let accentColor = user.accent_color || "";

    if (newAccent !== null) {
        if (newAccent !== "" && !ACCENT_REGEX.test(newAccent)) {
            return res.status(400).json({ error: "Color invalido" });
        }

        accentColor = newAccent;
    }

    const hideRegion = newHideRegion !== null ? newHideRegion : !!user.hide_region;
    const hideOnline = newHideOnline !== null ? newHideOnline : !!user.hide_online;

    try {
        const updated = await pool.query(
            `
            UPDATE users
            SET username = $2, region = $3, description = $4, accent_color = $5,
                status_text = $6, hide_region = $7, hide_online = $8
            WHERE id = $1
            RETURNING ${USER_COLUMNS}
            `,
            [userId, username, region, description, accentColor, statusText, hideRegion, hideOnline]
        );

        log("Profile updated", `${username} (${userId})`);

        res.json({ ok: true, user: getSelfUser(updated.rows[0]) });
    } catch (error) {
        if (error && error.code === "23505") {
            return res.status(409).json({ error: "Ese nombre ya existe" });
        }

        throw error;
    }
}));

app.post("/users/:id/region", requireAuth(claimParamId), profileLimiter, asyncHandler(async (req, res) => {
    const region = normalizeRegion(req.body.region);

    if (region && !isValidRegion(region)) {
        return res.status(400).json({ error: "La regi\u00f3n debe usar 2 letras" });
    }

    const updated = await pool.query(
        `UPDATE users SET region = $2 WHERE id = $1 RETURNING ${USER_COLUMNS}`,
        [req.actor.id, region]
    );

    res.json({ ok: true, user: getSelfUser(updated.rows[0]) });
}));

app.post(
    "/users/:id/avatar",
    requireAuth(claimParamId),
    avatarLimiter,
    upload.single("avatar"),
    asyncHandler(async (req, res) => {
        if (!req.file) {
            return res.status(400).json({ error: "Falta la imagen" });
        }

        await inspectImage(req.file.buffer);

        let moderationJpeg;
        let avatarWebp;

        try {
            moderationJpeg = await buildModerationJpeg(req.file.buffer);
            avatarWebp = await buildAvatarWebp(req.file.buffer);
        } catch {
            throw new HttpError(400, "No se pudo procesar la imagen");
        }

        let moderation;

        try {
            moderation = await moderateContent({ imageBuffer: moderationJpeg, imageMime: "image/jpeg" });
        } catch (error) {
            console.error("[MichuStudio] Moderation error", error.message);
            return res.status(503).json({ error: "No se pudo moderar la imagen" });
        }

        if (moderation.flagged) {
            return res.status(400).json({ error: "La foto de perfil no est\u00e1 permitida" });
        }

        const updated = await pool.query(
            `UPDATE users SET avatar_webp = $2 WHERE id = $1 RETURNING ${USER_COLUMNS}`,
            [req.actor.id, avatarWebp]
        );

        log("Avatar updated", `${req.actorRow.username} (${req.actor.id})`);

        res.json({ ok: true, user: getSelfUser(updated.rows[0]) });
    })
);

app.delete("/users/:id/avatar", requireAuth(claimParamId), avatarLimiter, asyncHandler(async (req, res) => {
    const updated = await pool.query(
        `UPDATE users SET avatar_webp = NULL WHERE id = $1 RETURNING ${USER_COLUMNS}`,
        [req.actor.id]
    );

    res.json({ ok: true, user: getSelfUser(updated.rows[0]) });
}));

app.post(
    "/users/:id/banner",
    requireAuth(claimParamId),
    bannerLimiter,
    upload.single("banner"),
    asyncHandler(async (req, res) => {
        if (!req.file) {
            return res.status(400).json({ error: "Falta la imagen" });
        }

        await inspectImage(req.file.buffer);

        let moderationJpeg;
        let bannerWebp;

        try {
            moderationJpeg = await buildBannerModerationJpeg(req.file.buffer);
            bannerWebp = await buildBannerWebp(req.file.buffer);
        } catch {
            throw new HttpError(400, "No se pudo procesar la imagen");
        }

        let moderation;

        try {
            moderation = await moderateContent({ imageBuffer: moderationJpeg, imageMime: "image/jpeg" });
        } catch (error) {
            console.error("[MichuStudio] Moderation error", error.message);
            return res.status(503).json({ error: "No se pudo moderar la imagen" });
        }

        if (moderation.flagged) {
            return res.status(400).json({ error: "El banner no est\u00e1 permitido" });
        }

        const updated = await pool.query(
            `UPDATE users SET banner_webp = $2 WHERE id = $1 RETURNING ${USER_COLUMNS}`,
            [req.actor.id, bannerWebp]
        );

        log("Banner updated", `${req.actorRow.username} (${req.actor.id})`);

        res.json({ ok: true, user: getSelfUser(updated.rows[0]) });
    })
);

app.delete("/users/:id/banner", requireAuth(claimParamId), bannerLimiter, asyncHandler(async (req, res) => {
    const updated = await pool.query(
        `UPDATE users SET banner_webp = NULL WHERE id = $1 RETURNING ${USER_COLUMNS}`,
        [req.actor.id]
    );

    res.json({ ok: true, user: getSelfUser(updated.rows[0]) });
}));

const sendFriendRequest = asyncHandler(async (req, res) => {
    const userId = req.actor.id;
    const friendId = cleanId(req.body.friendId);

    if (!isValidUserId(friendId)) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    if (friendId === userId) {
        return res.status(400).json({ error: "No te puedes agregar a ti mismo" });
    }

    const target = await loadUser(friendId);

    if (!target) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    if (target.is_banned || (await isBlockedBetween(userId, friendId))) {
        return res.status(403).json({ error: "No se puede enviar la solicitud" });
    }

    const self = req.actorRow;
    const alreadyFriends = Array.isArray(self.friends) && self.friends.map(String).includes(friendId);

    if (alreadyFriends) {
        return res.json({
            ok: true,
            status: "friends",
            user: getSelfUser(self),
            friend: getPublicProfile(target)
        });
    }

    const reverse = await pool.query(
        `SELECT 1 FROM friend_requests WHERE from_user_id = $1 AND to_user_id = $2 LIMIT 1`,
        [friendId, userId]
    );

    if (reverse.rows.length > 0) {
        const result = await acceptFriendship(userId, friendId);

        if (result.status !== 200) {
            return res.status(result.status).json({ error: result.error });
        }

        log("Friend added", `${result.userName} <-> ${result.friendName}`);

        return res.json({
            ok: true,
            status: "friends",
            user: getSelfUser(result.user),
            friend: getPublicProfile(result.friend)
        });
    }

    const outgoing = await pool.query(
        `SELECT COUNT(*)::int AS n FROM friend_requests WHERE from_user_id = $1`,
        [userId]
    );

    if (outgoing.rows[0].n >= MAX_OUTGOING_REQUESTS) {
        return res.status(400).json({ error: "Tienes demasiadas solicitudes pendientes" });
    }

    const incoming = await pool.query(
        `SELECT COUNT(*)::int AS n FROM friend_requests WHERE to_user_id = $1`,
        [friendId]
    );

    if (incoming.rows[0].n >= MAX_INCOMING_REQUESTS) {
        return res.status(400).json({ error: "Esa persona tiene demasiadas solicitudes pendientes" });
    }

    await pool.query(
        `INSERT INTO friend_requests (from_user_id, to_user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [userId, friendId]
    );

    res.json({
        ok: true,
        status: "pending",
        user: getSelfUser(self),
        friend: getPublicProfile(target)
    });
});

app.post("/friends/request", requireAuth(claimBody), friendsLimiter, sendFriendRequest);
app.post("/friends/add", requireAuth(claimBody), friendsLimiter, sendFriendRequest);

app.post("/friends/accept", requireAuth(claimBody), friendsLimiter, asyncHandler(async (req, res) => {
    const userId = req.actor.id;
    const friendId = cleanId(req.body.friendId);

    if (!isValidUserId(friendId) || friendId === userId) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const pending = await pool.query(
        `SELECT 1 FROM friend_requests WHERE from_user_id = $1 AND to_user_id = $2 LIMIT 1`,
        [friendId, userId]
    );

    if (pending.rows.length === 0) {
        return res.status(404).json({ error: "Solicitud no encontrada" });
    }

    const result = await acceptFriendship(userId, friendId);

    if (result.status !== 200) {
        return res.status(result.status).json({ error: result.error });
    }

    log("Friend added", `${result.userName} <-> ${result.friendName}`);

    res.json({
        ok: true,
        status: "friends",
        user: getSelfUser(result.user),
        friend: getPublicProfile(result.friend)
    });
}));

app.post("/friends/decline", requireAuth(claimBody), friendsLimiter, asyncHandler(async (req, res) => {
    const friendId = cleanId(req.body.friendId);

    if (!isValidUserId(friendId)) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    await pool.query(
        `DELETE FROM friend_requests WHERE from_user_id = $1 AND to_user_id = $2`,
        [friendId, req.actor.id]
    );

    res.json({ ok: true });
}));

app.post("/friends/cancel", requireAuth(claimBody), friendsLimiter, asyncHandler(async (req, res) => {
    const friendId = cleanId(req.body.friendId);

    if (!isValidUserId(friendId)) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    await pool.query(
        `DELETE FROM friend_requests WHERE from_user_id = $1 AND to_user_id = $2`,
        [req.actor.id, friendId]
    );

    res.json({ ok: true });
}));

app.get("/friends/requests", requireAuth(null), friendsLimiter, asyncHandler(async (req, res) => {
    const incoming = await pool.query(
        `
        SELECT ${USER_COLUMNS}
        FROM users
        WHERE id IN (SELECT from_user_id FROM friend_requests WHERE to_user_id = $1)
        ORDER BY lower(username) ASC
        LIMIT $2
        `,
        [req.actor.id, MAX_INCOMING_REQUESTS]
    );

    const outgoing = await pool.query(
        `
        SELECT ${USER_COLUMNS}
        FROM users
        WHERE id IN (SELECT to_user_id FROM friend_requests WHERE from_user_id = $1)
        ORDER BY lower(username) ASC
        LIMIT $2
        `,
        [req.actor.id, MAX_OUTGOING_REQUESTS]
    );

    res.json({
        ok: true,
        incoming: incoming.rows.map(getPublicProfile),
        outgoing: outgoing.rows.map(getPublicProfile)
    });
}));

app.post("/friends/remove", requireAuth(claimBody), friendsLimiter, asyncHandler(async (req, res) => {
    const userId = req.actor.id;
    const friendId = cleanId(req.body.friendId);

    if (!isValidUserId(friendId) || friendId === userId) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const result = await updateFriendship(userId, friendId, false);

    if (result.status !== 200) {
        return res.status(result.status).json({ error: result.error });
    }

    log("Friend removed", `${result.userName} <-> ${result.friendName}`);

    res.json({
        ok: true,
        user: getSelfUser(result.user),
        friend: result.friend ? getPublicProfile(result.friend) : null
    });
}));

app.post("/account/password", requireAuth(claimBody), passwordLimiter, asyncHandler(async (req, res) => {
    const current = String(req.body.currentPassword || "").slice(0, 256);
    const next = String(req.body.newPassword || "");

    if (!current || !next) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const passwordError = validatePassword(next);

    if (passwordError) {
        return res.status(400).json({ error: passwordError });
    }

    if (safeEqual(current, next)) {
        return res.status(400).json({ error: "La nueva contrase\u00f1a debe ser distinta" });
    }

    const ok = await bcrypt.compare(current, String(req.actorRow.password_hash || DUMMY_HASH));

    if (!ok) {
        return res.status(401).json({ error: "Contrase\u00f1a actual incorrecta" });
    }

    const hash = await bcrypt.hash(next, BCRYPT_ROUNDS);

    await pool.query(
        `UPDATE users SET password_hash = $2, token_valid_after = $3::timestamptz WHERE id = $1`,
        [req.actor.id, hash, new Date()]
    );

    log("Password changed", `${req.actorRow.username} (${req.actor.id})`);

    const session = createToken(req.actor.id);

    res.json({ ok: true, token: session.token, tokenExpiresAt: session.expiresAt });
}));

app.get("/blocks", requireAuth(null), blocksLimiter, asyncHandler(async (req, res) => {
    const result = await pool.query(
        `
        SELECT ${USER_COLUMNS}
        FROM users
        WHERE id IN (SELECT blocked_id FROM blocks WHERE user_id = $1)
        ORDER BY lower(username) ASC
        LIMIT $2
        `,
        [req.actor.id, MAX_BLOCKS]
    );

    res.json({ ok: true, users: result.rows.map(getPublicProfile) });
}));

app.post("/blocks/add", requireAuth(claimBody), blocksLimiter, asyncHandler(async (req, res) => {
    const userId = req.actor.id;
    const blockedId = cleanId(req.body.blockedId);

    if (!isValidUserId(blockedId) || blockedId === userId) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const target = await loadUser(blockedId);

    if (!target) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const count = await pool.query(
        `SELECT COUNT(*)::int AS n FROM blocks WHERE user_id = $1`,
        [userId]
    );

    if (count.rows[0].n >= MAX_BLOCKS) {
        return res.status(400).json({ error: "Limite de bloqueos alcanzado" });
    }

    await pool.query(
        `INSERT INTO blocks (user_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [userId, blockedId]
    );

    await updateFriendship(userId, blockedId, false);

    await pool.query(
        `DELETE FROM friend_requests WHERE (from_user_id = $1 AND to_user_id = $2) OR (from_user_id = $2 AND to_user_id = $1)`,
        [userId, blockedId]
    );

    log("User blocked", `${req.actorRow.username} -> ${target.username}`);

    res.json({ ok: true });
}));

app.post("/blocks/remove", requireAuth(claimBody), blocksLimiter, asyncHandler(async (req, res) => {
    const blockedId = cleanId(req.body.blockedId);

    if (!isValidUserId(blockedId)) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    await pool.query(
        `DELETE FROM blocks WHERE user_id = $1 AND blocked_id = $2`,
        [req.actor.id, blockedId]
    );

    res.json({ ok: true });
}));

app.get("/mail/:userId", requireAuth(claimParamUserId), asyncHandler(async (req, res) => {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), MAX_MAILS_PER_USER);

    const result = await pool.query(
        `
        SELECT id, to_user_id, from_user_id, type, message, created_at, is_read
        FROM mail
        WHERE to_user_id = $1
        ORDER BY created_at DESC, id DESC
        LIMIT $2
        `,
        [req.actor.id, limit]
    );

    res.json({ ok: true, mails: result.rows.map(mapMail) });
}));

app.post("/mail/send", requireAuth(claimBody), mailSendLimiter, mailPairLimiter, asyncHandler(async (req, res) => {
    const toUserId = cleanId(req.body.toUserId);
    const type = normalizeMailType(req.body.type);
    const message = cleanText(req.body.message, 2000);

    if (!isValidUserId(toUserId) || !type || !message) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    if (type !== "Normal") {
        return res.status(403).json({ error: "Solo la administraci\u00f3n puede enviar avisos" });
    }

    if (!req.actorViaToken) {
        const password = String(req.body.password || "").slice(0, 256);
        const passwordOk = password
            ? await bcrypt.compare(password, String(req.actorRow.password_hash || ""))
            : false;

        if (!passwordOk) {
            return res.status(401).json({ error: "Contrase\u00f1a incorrecta" });
        }
    }

    const receiver = await loadUser(toUserId);

    if (!receiver) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    if (await isBlockedBetween(req.actor.id, toUserId)) {
        return res.status(403).json({ error: "No puedes enviar mensajes a esta persona" });
    }

    if (MODERATE_MAIL) {
        let moderation;

        try {
            moderation = await moderateContent({ text: message });
        } catch (error) {
            console.error("[MichuStudio] Moderation error", error.message);
            return res.status(503).json({ error: "No se pudo comprobar el mensaje" });
        }

        if (moderation.flagged) {
            return res.status(400).json({ error: "El mensaje no est\u00e1 permitido" });
        }
    }

    const mail = await insertMail(toUserId, req.actor.id, type, message);

    res.json({ ok: true, mail: mapMail(mail) });
}));

app.post("/mail/:id/read", requireAuth(claimBody), asyncHandler(async (req, res) => {
    const mailId = cleanId(req.params.id);

    if (!/^\d{1,18}$/.test(mailId)) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    const result = await pool.query(
        `UPDATE mail SET is_read = TRUE WHERE id = $1 AND to_user_id = $2 RETURNING id`,
        [mailId, req.actor.id]
    );

    if (result.rows.length === 0) {
        return res.status(404).json({ error: "Correo no encontrado" });
    }

    res.json({ ok: true });
}));

app.get("/forum/posts", asyncHandler(async (req, res) => {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 100);
    const result = await pool.query(
        `SELECT p.id, p.user_id, u.username, p.title, p.body, p.created_at,
                (SELECT COUNT(*)::int FROM forum_comments c WHERE c.post_id = p.id) AS comment_count
         FROM forum_posts p LEFT JOIN users u ON u.id = p.user_id
         ORDER BY p.created_at DESC, p.id DESC LIMIT $1`,
        [limit]
    );
    res.json({ ok: true, posts: result.rows.map((row) => ({
        id: String(row.id), userId: String(row.user_id), username: String(row.username || "Cuenta eliminada"),
        title: String(row.title), body: String(row.body), createdAt: new Date(row.created_at).toISOString(),
        commentCount: Number(row.comment_count || 0)
    })) });
}));

app.post("/forum/posts", requireAuth(claimBody), forumLimiter, asyncHandler(async (req, res) => {
    const title = cleanText(req.body.title, 100);
    const body = cleanText(req.body.body, 3000);
    if (title.length < 3 || body.length < 3) {
        return res.status(400).json({ error: "El titulo y el mensaje necesitan al menos 3 caracteres" });
    }
    let moderation;
    try {
        moderation = await moderateContent({ text: `${title}\n${body}` });
    } catch (error) {
        console.error("[MichuStudio] Forum moderation error", error.message);
        return res.status(503).json({ error: "No se pudo revisar el mensaje ahora" });
    }
    if (moderation.flagged) {
        return res.status(400).json({ error: "Ese texto no está permitido" });
    }
    const result = await pool.query(
        `INSERT INTO forum_posts (user_id, title, body) VALUES ($1, $2, $3) RETURNING id, user_id, title, body, created_at`,
        [req.actor.id, title, body]
    );
    const row = result.rows[0];
    res.status(201).json({ ok: true, post: { id: String(row.id), userId: String(row.user_id), username: req.actorRow.username,
        title: row.title, body: row.body, createdAt: new Date(row.created_at).toISOString(), commentCount: 0 } });
}));

app.get("/forum/posts/:id/comments", asyncHandler(async (req, res) => {
    const postId = cleanId(req.params.id);
    if (!/^\d{1,18}$/.test(postId)) return res.status(400).json({ error: "Publicación invalida" });
    const exists = await pool.query(`SELECT 1 FROM forum_posts WHERE id = $1`, [postId]);
    if (!exists.rows.length) return res.status(404).json({ error: "Publicación no encontrada" });
    const result = await pool.query(
        `SELECT c.id, c.user_id, u.username, c.body, c.created_at FROM forum_comments c LEFT JOIN users u ON u.id = c.user_id WHERE c.post_id = $1 ORDER BY c.created_at ASC, c.id ASC LIMIT 200`,
        [postId]
    );
    res.json({ ok: true, comments: result.rows.map((row) => ({ id: String(row.id), userId: String(row.user_id), username: String(row.username || "Cuenta eliminada"), body: String(row.body), createdAt: new Date(row.created_at).toISOString() })) });
}));

app.post("/forum/posts/:id/comments", requireAuth(claimBody), forumLimiter, asyncHandler(async (req, res) => {
    const postId = cleanId(req.params.id);
    const body = cleanText(req.body.body, 1500);
    if (!/^\d{1,18}$/.test(postId) || body.length < 2) return res.status(400).json({ error: "Comentario invalido" });
    const exists = await pool.query(`SELECT 1 FROM forum_posts WHERE id = $1`, [postId]);
    if (!exists.rows.length) return res.status(404).json({ error: "Publicación no encontrada" });
    let moderation;
    try {
        moderation = await moderateContent({ text: body });
    } catch (error) {
        console.error("[MichuStudio] Forum comment moderation error", error.message);
        return res.status(503).json({ error: "No se pudo revisar el comentario ahora" });
    }
    if (moderation.flagged) return res.status(400).json({ error: "Ese texto no está permitido" });
    const result = await pool.query(`INSERT INTO forum_comments (post_id, user_id, body) VALUES ($1, $2, $3) RETURNING id, user_id, body, created_at`, [postId, req.actor.id, body]);
    const row = result.rows[0];
    res.status(201).json({ ok: true, comment: { id: String(row.id), userId: String(row.user_id), username: req.actorRow.username, body: row.body, createdAt: new Date(row.created_at).toISOString() } });
}));

app.use((req, res) => {
    res.status(404).json({ error: "Endpoint no encontrado" });
});

app.use((error, req, res, next) => {
    if (res.headersSent) {
        return next(error);
    }

    if (error instanceof HttpError) {
        return res.status(error.status).json({ error: error.message });
    }

    if (error && error.type === "entity.too.large") {
        return res.status(413).json({ error: "Solicitud demasiado grande" });
    }

    if (error && error.type === "entity.parse.failed") {
        return res.status(400).json({ error: "JSON invalido" });
    }

    if (error && error.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({ error: "La imagen supera los 5 MB" });
    }

    if (error instanceof multer.MulterError) {
        return res.status(400).json({ error: "Archivo invalido" });
    }

    if (error && Number.isInteger(error.status) && error.status >= 400 && error.status < 500) {
        return res.status(error.status).json({ error: "Solicitud invalida" });
    }

    console.error(error);

    res.status(500).json({ error: "Error del servidor" });
});

let httpServer = null;
let shuttingDown = false;

async function shutdown(signal) {
    if (shuttingDown) {
        return;
    }

    shuttingDown = true;

    log("Cerrando", signal);

    setTimeout(() => process.exit(1), 10000).unref();

    try {
        if (httpServer) {
            await new Promise((resolve) => httpServer.close(resolve));
        }

        await pool.end();
    } finally {
        process.exit(0);
    }
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

process.on("unhandledRejection", (reason) => {
    console.error("[MichuStudio] Unhandled rejection", reason);
});

process.on("uncaughtException", (error) => {
    console.error("[MichuStudio] Uncaught exception", error);
    process.exit(1);
});

async function start() {
    try {
        await initDb();
        await repairAllUsers();
        await migrateAvatars();

        httpServer = app.listen(PORT, () => {
            log(`MichuStudio server running on ${PORT}`);
        });

        httpServer.keepAliveTimeout = 120000;
        httpServer.headersTimeout = 125000;
        httpServer.requestTimeout = 60000;
    } catch (error) {
        console.error(error);
        process.exit(1);
    }
}

start();
