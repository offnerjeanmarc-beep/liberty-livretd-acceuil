const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { URL } = require("node:url");
const QRCode = require("qrcode");
const { createDatabase } = require("./database");

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const DB_PATH = path.join(DATA_DIR, "liberty.sqlite");
const PORT = Number(process.env.PORT || 4173);
const BASE_URL = process.env.BASE_URL || `http://127.0.0.1:${PORT}`;
const SESSION_SECRET = process.env.SESSION_SECRET || "local-liberty-dev-secret";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-me-before-production";
const FORCE_HTTPS = process.env.FORCE_HTTPS === "true";
const DEFAULT_OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5.5";
const ADMIN_LOGIN_MAX_ATTEMPTS = 6;
const ADMIN_LOGIN_WINDOW_MS = 15 * 60 * 1000;
const adminLoginAttempts = new Map();

fs.mkdirSync(DATA_DIR, { recursive: true });
let db;

async function run(sql, params = []) {
  return db.run(sql, params);
}

async function get(sql, params = []) {
  return db.get(sql, params);
}

async function all(sql, params = []) {
  return db.all(sql, params);
}

function now() {
  return new Date().toISOString();
}

function json(value, fallback) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function assertIdentifier(value) {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value)) {
    throw new Error(`Invalid SQL identifier: ${value}`);
  }
  return value;
}

async function columnExists(table, column) {
  assertIdentifier(table);
  assertIdentifier(column);
  if (db.dialect === "mysql") {
    const rows = await all(
      "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?",
      [table, column],
    );
    return rows.length > 0;
  }
  return (await all(`PRAGMA table_info(${table})`)).some((item) => item.name === column);
}

async function ensureColumn(table, column, definition) {
  if (!(await columnExists(table, column))) {
    await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${db.dialect === "mysql" ? mysqlColumnDefinition(column, definition) : definition}`);
  }
}

function mysqlColumnDefinition(column, fallback) {
  const definitions = {
    wifi_ssid: "VARCHAR(180) NOT NULL DEFAULT ''",
    wifi_password: "VARCHAR(180) NOT NULL DEFAULT ''",
    ai_daily_limit: "INT NOT NULL DEFAULT 80",
    ai_session_limit: "INT NOT NULL DEFAULT 20",
    ai_max_input_chars: "INT NOT NULL DEFAULT 700",
    public_description: "LONGTEXT NULL",
    direct_booking_json: "LONGTEXT NULL",
    session_id: "VARCHAR(80) NOT NULL DEFAULT ''",
  };
  return definitions[column] || fallback;
}

function isSecureRequest(req) {
  return req.headers["x-forwarded-proto"] === "https" || req.socket.encrypted || BASE_URL.startsWith("https://");
}

function shouldRedirectHttps(req) {
  return FORCE_HTTPS && req.method === "GET" && !isSecureRequest(req);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 32, "sha256").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(":")) return false;
  const [salt, hash] = stored.split(":");
  const attempt = hashPassword(password, salt).split(":")[1];
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(attempt, "hex"));
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function makeToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encoded}.${sign(encoded)}`;
}

function readToken(req, name) {
  const cookies = Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map((part) => part.trim().split("="))
      .filter((part) => part.length === 2)
  );
  const token = cookies[name];
  if (!token || !token.includes(".")) return null;
  const [encoded, signature] = token.split(".");
  if (signature !== sign(encoded)) return null;
  try {
    return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function cookie(req, name, value, maxAge = 60 * 60 * 8) {
  const secure = isSecureRequest(req) ? "; Secure" : "";
  return `${name}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

function clearCookie(name) {
  return `${name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
}

function csrfToken(scope) {
  return makeToken({ type: "csrf", scope, ts: Date.now() });
}

function verifyCsrf(token, scope) {
  const [encoded, signature] = String(token || "").split(".");
  if (!encoded || !signature || signature !== sign(encoded)) return false;
  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    return payload.type === "csrf" && payload.scope === scope && Date.now() - payload.ts < 2 * 60 * 60 * 1000;
  } catch {
    return false;
  }
}

function csrfField(scope) {
  return `<input type="hidden" name="csrf" value="${escapeHtml(csrfToken(scope))}" />`;
}

function securityHeaders(extra = {}) {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    ...extra,
  };
}

function clientIp(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "local").split(",")[0].trim();
}

function isAdminRateLimited(req) {
  const ip = clientIp(req);
  const entry = adminLoginAttempts.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.firstAttempt > ADMIN_LOGIN_WINDOW_MS) {
    adminLoginAttempts.delete(ip);
    return false;
  }
  return entry.count >= ADMIN_LOGIN_MAX_ATTEMPTS;
}

function recordAdminLoginAttempt(req, success) {
  const ip = clientIp(req);
  if (success) {
    adminLoginAttempts.delete(ip);
    return;
  }
  const entry = adminLoginAttempts.get(ip);
  if (!entry || Date.now() - entry.firstAttempt > ADMIN_LOGIN_WINDOW_MS) {
    adminLoginAttempts.set(ip, { count: 1, firstAttempt: Date.now() });
    return;
  }
  entry.count += 1;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function slugify(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 72);
}

function safeJsonForScript(value) {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

async function createMysqlTables() {
  await run(`CREATE TABLE IF NOT EXISTS properties (
    id INT AUTO_INCREMENT PRIMARY KEY,
    slug VARCHAR(120) UNIQUE NOT NULL,
    name VARCHAR(180) NOT NULL,
    status VARCHAR(40) NOT NULL DEFAULT 'active',
    city VARCHAR(120) NOT NULL DEFAULT '',
    cover_image VARCHAR(255) NOT NULL DEFAULT '/assets/liberty-hero.png',
    traveler_password_hash VARCHAR(255) NOT NULL,
    openai_api_key LONGTEXT NOT NULL,
    openai_model VARCHAR(80) NOT NULL DEFAULT 'gpt-5.5',
    ai_instructions LONGTEXT NOT NULL,
    welcome LONGTEXT NOT NULL,
    address LONGTEXT NOT NULL,
    gps VARCHAR(120) NOT NULL DEFAULT '',
    wifi_ssid VARCHAR(180) NOT NULL DEFAULT '',
    wifi_password VARCHAR(180) NOT NULL DEFAULT '',
    ai_daily_limit INT NOT NULL DEFAULT 80,
    ai_session_limit INT NOT NULL DEFAULT 20,
    ai_max_input_chars INT NOT NULL DEFAULT 700,
    public_description LONGTEXT NOT NULL,
    direct_booking_json LONGTEXT NOT NULL,
    data_json LONGTEXT NOT NULL,
    created_at VARCHAR(40) NOT NULL,
    updated_at VARCHAR(40) NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  await run(`CREATE TABLE IF NOT EXISTS service_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    property_id INT NOT NULL,
    type VARCHAR(120) NOT NULL,
    guest_name VARCHAR(180) NOT NULL DEFAULT '',
    message LONGTEXT NOT NULL,
    status VARCHAR(40) NOT NULL DEFAULT 'new',
    created_at VARCHAR(40) NOT NULL,
    INDEX(property_id),
    CONSTRAINT fk_service_property FOREIGN KEY(property_id) REFERENCES properties(id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  await run(`CREATE TABLE IF NOT EXISTS chat_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    property_id INT NOT NULL,
    role VARCHAR(40) NOT NULL,
    content LONGTEXT NOT NULL,
    session_id VARCHAR(80) NOT NULL DEFAULT '',
    created_at VARCHAR(40) NOT NULL,
    INDEX(property_id),
    INDEX(session_id),
    CONSTRAINT fk_chat_property FOREIGN KEY(property_id) REFERENCES properties(id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  await run(`CREATE TABLE IF NOT EXISTS crm_leads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    property_id INT NOT NULL,
    first_name VARCHAR(120) NOT NULL DEFAULT '',
    email VARCHAR(180) NOT NULL DEFAULT '',
    phone VARCHAR(80) NOT NULL DEFAULT '',
    stay_dates VARCHAR(160) NOT NULL DEFAULT '',
    marketing_consent TINYINT(1) NOT NULL DEFAULT 0,
    created_at VARCHAR(40) NOT NULL,
    INDEX(property_id),
    CONSTRAINT fk_crm_property FOREIGN KEY(property_id) REFERENCES properties(id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  await run(`CREATE TABLE IF NOT EXISTS analytics_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    property_id INT NULL,
    event_name VARCHAR(120) NOT NULL,
    event_value VARCHAR(255) NOT NULL DEFAULT '',
    session_id VARCHAR(80) NOT NULL DEFAULT '',
    created_at VARCHAR(40) NOT NULL,
    INDEX(property_id),
    INDEX(event_name),
    CONSTRAINT fk_analytics_property FOREIGN KEY(property_id) REFERENCES properties(id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  await run(`CREATE TABLE IF NOT EXISTS city_pois (
    id INT AUTO_INCREMENT PRIMARY KEY,
    city VARCHAR(120) NOT NULL,
    type VARCHAR(80) NOT NULL,
    title VARCHAR(180) NOT NULL,
    description LONGTEXT NOT NULL,
    distance VARCHAR(80) NOT NULL DEFAULT '',
    address VARCHAR(255) NOT NULL DEFAULT '',
    maps_url VARCHAR(500) NOT NULL DEFAULT '',
    external_url VARCHAR(500) NOT NULL DEFAULT '',
    created_at VARCHAR(40) NOT NULL,
    updated_at VARCHAR(40) NOT NULL,
    INDEX(city),
    INDEX(type)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  await run(`CREATE TABLE IF NOT EXISTS property_pois (
    property_id INT NOT NULL,
    poi_id INT NOT NULL,
    sort_order INT NOT NULL DEFAULT 0,
    PRIMARY KEY(property_id, poi_id),
    CONSTRAINT fk_property_pois_property FOREIGN KEY(property_id) REFERENCES properties(id),
    CONSTRAINT fk_property_pois_poi FOREIGN KEY(poi_id) REFERENCES city_pois(id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  await run(`CREATE TABLE IF NOT EXISTS admin_settings (
    \`key\` VARCHAR(120) PRIMARY KEY,
    value LONGTEXT NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
}

async function initDb() {
  if (db.dialect === "mysql") {
    await createMysqlTables();
  } else {
  await run(`CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    city TEXT NOT NULL DEFAULT '',
    cover_image TEXT NOT NULL DEFAULT '/assets/liberty-hero.png',
    traveler_password_hash TEXT NOT NULL,
    openai_api_key TEXT NOT NULL DEFAULT '',
    openai_model TEXT NOT NULL DEFAULT 'gpt-5.5',
    ai_instructions TEXT NOT NULL DEFAULT '',
    welcome TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    gps TEXT NOT NULL DEFAULT '',
    wifi_ssid TEXT NOT NULL DEFAULT '',
    wifi_password TEXT NOT NULL DEFAULT '',
    ai_daily_limit INTEGER NOT NULL DEFAULT 80,
    ai_session_limit INTEGER NOT NULL DEFAULT 20,
    ai_max_input_chars INTEGER NOT NULL DEFAULT 700,
    public_description TEXT NOT NULL DEFAULT '',
    direct_booking_json TEXT NOT NULL DEFAULT '{}',
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS service_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    guest_name TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    created_at TEXT NOT NULL,
    FOREIGN KEY(property_id) REFERENCES properties(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY(property_id) REFERENCES properties(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS crm_leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL,
    first_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    stay_dates TEXT NOT NULL DEFAULT '',
    marketing_consent INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(property_id) REFERENCES properties(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS analytics_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER,
    event_name TEXT NOT NULL,
    event_value TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY(property_id) REFERENCES properties(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS city_pois (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    city TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    distance TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    maps_url TEXT NOT NULL DEFAULT '',
    external_url TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS property_pois (
    property_id INTEGER NOT NULL,
    poi_id INTEGER NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(property_id, poi_id),
    FOREIGN KEY(property_id) REFERENCES properties(id),
    FOREIGN KEY(poi_id) REFERENCES city_pois(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS admin_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`);
  }

  await ensureColumn("properties", "wifi_ssid", "TEXT NOT NULL DEFAULT ''");
  await ensureColumn("properties", "wifi_password", "TEXT NOT NULL DEFAULT ''");
  await ensureColumn("properties", "ai_daily_limit", "INTEGER NOT NULL DEFAULT 80");
  await ensureColumn("properties", "ai_session_limit", "INTEGER NOT NULL DEFAULT 20");
  await ensureColumn("properties", "ai_max_input_chars", "INTEGER NOT NULL DEFAULT 700");
  await ensureColumn("properties", "public_description", "TEXT NOT NULL DEFAULT ''");
  await ensureColumn("properties", "direct_booking_json", "TEXT NOT NULL DEFAULT '{}'");
  await ensureColumn("chat_messages", "session_id", "TEXT NOT NULL DEFAULT ''");

  await run("UPDATE properties SET openai_model = ? WHERE openai_model IS NULL OR openai_model = ''", [DEFAULT_OPENAI_MODEL]);

  if (!(await get("SELECT value FROM admin_settings WHERE `key` = ?", ["admin_password_hash"]))) {
    await run("INSERT INTO admin_settings (`key`, value) VALUES (?, ?)", [
      "admin_password_hash",
      hashPassword(ADMIN_PASSWORD),
    ]);
  }

  if ((await get("SELECT COUNT(*) AS count FROM properties")).count === 0) {
    await seedProperty("Appartement Cathédrale", "appartement-cathedrale", "CATHEDRALE2026", "Strasbourg", "Vue élégante au coeur du centre historique, à proximité de la Cathédrale.", {
      address: "12 Rue des Orfèvres, 67000 Strasbourg",
      gps: "48.5819, 7.7507",
      parking: "Parking Gutenberg conseillé, 4 minutes à pied.",
      keybox: "Boîte à clés noire à droite de l'entrée, code transmis dans Mon Séjour.",
      checkin: "Arrivée autonome à partir de 16h00.",
      checkout: "Départ avant 10h00.",
      wifi: { network: "Liberty-Cathedrale", password: "LIBERTY-WIFI-2026" },
    });
    await seedProperty("Studio Gare", "studio-gare", "GARE2026", "Strasbourg", "Studio premium pensé pour les arrivées rapides et les séjours professionnels.", {
      address: "8 Rue du Maire Kuss, 67000 Strasbourg",
      gps: "48.5845, 7.7357",
      parking: "Parking Wodli ou gare courte durée selon disponibilité.",
      keybox: "Coffret sécurisé dans le hall, code personnel à renseigner dans Mon Séjour.",
      checkin: "Arrivée autonome à partir de 15h00.",
      checkout: "Départ avant 11h00.",
      wifi: { network: "Liberty-Gare", password: "GARE-PREMIUM-2026" },
    });
    await seedProperty("Duplex Centre", "duplex-centre", "DUPLEX2026", "Strasbourg", "Duplex familial avec prestations complètes et accès direct aux bonnes adresses Liberty.", {
      address: "4 Rue des Serruriers, 67000 Strasbourg",
      gps: "48.5808, 7.7485",
      parking: "Parking Austerlitz conseillé.",
      keybox: "Remise des clés via boîte sécurisée dans la cour intérieure.",
      checkin: "Arrivée autonome à partir de 16h00.",
      checkout: "Départ avant 10h00.",
      wifi: { network: "Liberty-Duplex", password: "DUPLEX-CONFORT-2026" },
    });
  }

  await backfillWifiColumns();
  await backfillOperationalData();
  await seedSharedPois();
}

async function backfillWifiColumns() {
  const properties = await all("SELECT id, data_json, wifi_ssid, wifi_password FROM properties");
  for (const property of properties) {
    const data = json(property.data_json, {});
    const wifi = normalizeWifi(data, property);
    if (!property.wifi_ssid && wifi.ssid) {
      await run("UPDATE properties SET wifi_ssid = ?, wifi_password = ? WHERE id = ?", [wifi.ssid, wifi.password, property.id]);
    }
  }
}

async function seedSharedPois() {
  if ((await get("SELECT COUNT(*) AS count FROM city_pois")).count > 0) return;
  const pois = [
    ["Strasbourg", "restaurant", "Maison Kammerzell", "Institution alsacienne face à la Cathédrale.", "8 min", "16 Pl. de la Cathédrale, 67000 Strasbourg", "https://www.google.com/maps/search/?api=1&query=Maison+Kammerzell+Strasbourg", "https://www.maison-kammerzell.com/"],
    ["Strasbourg", "monument", "Cathédrale Notre-Dame de Strasbourg", "Visite incontournable du centre historique.", "7 min", "Place de la Cathédrale, 67000 Strasbourg", "https://www.google.com/maps/search/?api=1&query=Cath%C3%A9drale+Notre-Dame+de+Strasbourg", "https://www.visitstrasbourg.fr/"],
    ["Strasbourg", "quartier", "Petite France", "Promenade patrimoniale, canaux et maisons à colombages.", "14 min", "Petite France, Strasbourg", "https://www.google.com/maps/search/?api=1&query=Petite+France+Strasbourg", "https://www.visitstrasbourg.fr/"],
    ["Strasbourg", "transport", "Gare de Strasbourg", "Gare TGV et accès tram vers le centre.", "10 min", "20 Pl. de la Gare, 67000 Strasbourg", "https://www.google.com/maps/search/?api=1&query=Gare+de+Strasbourg", "https://www.garesetconnexions.sncf/"],
    ["Strasbourg", "parking", "Parking Gutenberg", "Parking central pratique pour les séjours en coeur de ville.", "4 min", "Place Gutenberg, 67000 Strasbourg", "https://www.google.com/maps/search/?api=1&query=Parking+Gutenberg+Strasbourg", ""],
    ["Strasbourg", "transport", "Aéroport Strasbourg-Entzheim", "Aéroport relié à Strasbourg par navette train.", "25 min", "Route de Strasbourg, 67960 Entzheim", "https://www.google.com/maps/search/?api=1&query=A%C3%A9roport+Strasbourg+Entzheim", "https://www.strasbourg.aeroport.fr/"],
  ];
  for (const poi of pois) {
    await run(
      `INSERT INTO city_pois (city, type, title, description, distance, address, maps_url, external_url, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [...poi, now(), now()]
    );
  }
}

function mergeMissing(base, current) {
  if (Array.isArray(base)) return Array.isArray(current) && current.length ? current : base;
  if (!base || typeof base !== "object") return current ?? base;
  const merged = { ...(current && typeof current === "object" && !Array.isArray(current) ? current : {}) };
  for (const [key, value] of Object.entries(base)) {
    if (merged[key] === undefined || merged[key] === null || merged[key] === "") {
      merged[key] = value;
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      merged[key] = mergeMissing(value, merged[key]);
    }
  }
  return merged;
}

async function backfillOperationalData() {
  const defaults = defaultPropertyData();
  const properties = await all("SELECT id, data_json FROM properties");
  for (const property of properties) {
    const current = json(property.data_json, {});
    const merged = mergeMissing(defaults, current);
    await run("UPDATE properties SET data_json = ?, updated_at = ? WHERE id = ?", [JSON.stringify(merged), now(), property.id]);
  }
}

function defaultPropertyData(overrides = {}) {
  return {
    stay: {
      guestName: "Voyageur Liberty",
      dates: "Dates à personnaliser",
      accessCode: "Code transmis avant arrivée",
      messages: ["Bienvenue dans votre espace voyageurs Liberty.", "Toutes les informations essentielles sont centralisées ici."],
    },
    arrival: {
      parking: overrides.parking || "Parking à compléter dans l'administration.",
      keybox: overrides.keybox || "Procédure de remise des clés à compléter.",
      checkin: overrides.checkin || "Arrivée à partir de 16h00.",
      video: "Lien vidéo tutoriel à ajouter.",
    },
    departure: {
      checkout: overrides.checkout || "Départ avant 10h00.",
      checklist: ["Fermer les fenêtres", "Éteindre les lumières", "Déposer les clés selon la procédure", "Signaler toute anomalie"],
      cleaning: "Merci de laisser le logement dans un état correct. Le ménage professionnel est assuré par Liberty.",
    },
    equipment: {
      wifi: overrides.wifi || { network: "Liberty-Wifi", password: "À compléter" },
      items: [
        { name: "TV", details: "Télécommande dans le salon. Redémarrer la box si l'image ne s'affiche pas." },
        { name: "Climatisation", details: "Mode froid uniquement fenêtres fermées." },
        { name: "Chauffage", details: "Réglage recommandé entre 19 et 21 degrés." },
        { name: "Cuisine", details: "Équipements complets pour un séjour autonome." },
        { name: "Lave-linge", details: "Programme rapide conseillé pour petites charges." },
        { name: "Cafetière", details: "Capsules compatibles à préciser selon le logement." },
      ],
    },
    rules: [
      "Logement non-fumeur sauf indication contraire.",
      "Respect du voisinage et des heures de calme de la résidence.",
      "Fêtes et événements non autorisés sans validation préalable.",
      "Animaux acceptés uniquement si le mandat ou l'annonce le prévoit.",
    ],
    housingGuide: [
      { title: "Tableau électrique", text: "En cas de coupure, vérifier d'abord le disjoncteur principal.", media: "Photo ou vidéo à ajouter." },
      { title: "Électroménager", text: "Les notices utiles peuvent être ajoutées depuis l'administration.", media: "Tutoriel à ajouter." },
      { title: "Canapé-lit", text: "Préparer uniquement si l'option est prévue dans la réservation.", media: "Vidéo à ajouter." },
    ],
    assistance: [
      { title: "Fuite d'eau", text: "Couper l'arrivée d'eau si accessible puis créer une demande urgente." },
      { title: "Coupure internet", text: "Redémarrer la box, patienter 3 minutes, puis solliciter Liberty." },
      { title: "Coupure électrique", text: "Vérifier le tableau électrique avant d'ouvrir une demande." },
      { title: "Urgence", text: "Appeler le 112 en cas de danger immédiat, puis informer Liberty." },
    ],
    city: {
      highlights: ["Maison Kammerzell", "Cathédrale Notre-Dame de Strasbourg", "Petite France"],
      restaurants: ["Maison Kammerzell", "Le Tire-Bouchon", "Au Crocodile"],
      bars: ["Code Bar", "Les Aviateurs"],
      bakeries: ["Boulangerie Woerlé", "Pâtisserie Christian"],
      activities: ["Visite de la Cathédrale", "Balade en bateau", "Musée Alsacien"],
      bonsPlans: [
        { title: "Maison Kammerzell", description: "Institution alsacienne face à la Cathédrale.", distance: "8 min", address: "16 Pl. de la Cathédrale, 67000 Strasbourg", externalUrl: "https://www.maison-kammerzell.com/" },
        { title: "Petite France", description: "Quartier historique idéal pour une promenade patrimoniale.", distance: "14 min", address: "Petite France, Strasbourg", externalUrl: "https://www.visitstrasbourg.fr/" },
      ],
      transports: [
        { title: "Gare de Strasbourg", description: "Accès TGV, tram et taxis.", distance: "10 min", address: "20 Pl. de la Gare, 67000 Strasbourg", externalUrl: "https://www.garesetconnexions.sncf/" },
        { title: "Aéroport Strasbourg-Entzheim", description: "Navette train et taxis vers Strasbourg.", distance: "25 min", address: "Aéroport Strasbourg-Entzheim", externalUrl: "https://www.strasbourg.aeroport.fr/" },
      ],
      guides: [
        { title: "Que faire en 24h", text: "Cathédrale, Petite France, dîner alsacien et promenade sur les quais." },
        { title: "Que faire en 48h", text: "Ajouter les musées, Neustadt et une expérience gastronomique." },
        { title: "En famille", text: "Parcs, bateau, musées interactifs et pauses gourmandes." },
        { title: "En couple", text: "Balade au coucher du soleil, table intimiste et quartier historique." },
        { title: "Quand il pleut", text: "Musées, cafés, boutiques couvertes et visites guidées." },
      ],
      transport: ["Tram CTS", "Bus centre-ville", "Gare de Strasbourg", "Aéroport Strasbourg-Entzheim", "Taxi et VTC"],
    },
    services: [
      { title: "Late check-out", price: "Sur demande", text: "Départ tardif selon disponibilité opérationnelle." },
      { title: "Early check-in", price: "Sur demande", text: "Arrivée anticipée selon planning ménage." },
      { title: "Ménage intermédiaire", price: "À partir de 45€", text: "Remise en état pendant le séjour." },
      { title: "Lit bébé", price: "20€", text: "Installation avant arrivée." },
      { title: "Pack romantique", price: "49€", text: "Ambiance premium, fleurs ou attentions selon disponibilité." },
      { title: "Champagne", price: "39€", text: "Bouteille préparée au frais avant arrivée." },
      { title: "Courses avant arrivée", price: "Sur devis", text: "Sélection de produits déposés dans le logement." },
      { title: "Transfert gare/aéroport", price: "Sur devis", text: "Organisation d'un transport partenaire." },
    ],
    directBooking: {
      title: "Réservation Directe Liberty",
      text: "Bénéficiez d'offres spéciales, de codes fidélité et d'un contact direct pour vos prochains séjours.",
      promo: "LIBERTY-VIP",
      price: "Sur demande",
      availability: "Calendrier à connecter",
      photos: ["/assets/liberty-hero.png"],
      cta: "Demander une réservation directe",
    },
    contacts: {
      liberty: "contact@conciergerie-liberty.fr",
      emergency: "112",
      phone: "+33 0 00 00 00 00",
    },
    loyalty: {
      benefits: ["Réduction client récurrent", "Avantages VIP", "Cadeaux selon saison", "Offres propriétaires partenaires"],
    },
    futureModules: {
      ownerArea: "Espace propriétaire prêt à raccorder.",
      statistics: "Statistiques voyageurs et demandes prêtes à activer.",
      directPayment: "Paiement services et réservation directe à brancher avant production.",
    },
  };
}

async function seedProperty(name, slug, password, city, welcome, overrides) {
  const data = defaultPropertyData(overrides);
  await run(
    `INSERT INTO properties
      (slug, name, city, traveler_password_hash, welcome, address, gps, data_json, ai_instructions, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      slug,
      name,
      city,
      hashPassword(password),
      welcome,
      overrides.address,
      overrides.gps,
      JSON.stringify(data),
      "Tu es l'Assistant IA Liberty. Réponds avec élégance, précision et concision. Utilise uniquement les informations du logement et les consignes Liberty. Si une information manque, invite le voyageur à créer une demande dans le Centre de Services Liberty.",
      now(),
      now(),
    ]
  );
}

async function propertyBySlug(slug) {
  return await get("SELECT * FROM properties WHERE slug = ? AND status != 'archived'", [slug]);
}

function publicProperty(property) {
  const data = json(property.data_json, {});
  return {
    id: property.id,
    slug: property.slug,
    name: property.name,
    city: property.city,
    coverImage: property.cover_image,
    welcome: property.welcome,
    address: property.address,
    gps: property.gps,
    url: `${BASE_URL}/sejour/${property.slug}`,
    data,
  };
}

function normalizeWifi(data, property = {}) {
  return {
    ssid: property.wifi_ssid || data.wifi_ssid || data.equipment?.wifi?.ssid || data.equipment?.wifi?.network || "",
    password: property.wifi_password || data.wifi_password || data.equipment?.wifi?.password || "",
    encryption: data.equipment?.wifi?.encryption || "WPA",
  };
}

function mapsUrl(address, gps = "") {
  const query = address || gps || "";
  return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(query)}`;
}

function appleMapsUrl(address, gps = "") {
  const query = address || gps || "";
  return `https://maps.apple.com/?q=${encodeURIComponent(query)}`;
}

function poiMapsUrl(poi) {
  return poi.maps_url || mapsUrl(poi.address || poi.title);
}

function listToTextarea(value) {
  if (Array.isArray(value)) return value.join("\n");
  return String(value || "");
}

function textareaToList(value) {
  return String(value || "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function cardsToTextarea(items) {
  return (items || [])
    .map((item) => [item.title, item.description || item.text || "", item.distance || "", item.address || "", item.externalUrl || item.external_url || ""].join(" | "))
    .join("\n");
}

function textareaToCards(value) {
  return String(value || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [title, description = "", distance = "", address = "", externalUrl = ""] = line.split("|").map((part) => part.trim());
      return { title, description, distance, address, externalUrl };
    });
}

function renderFooter() {
  return `<footer class="legal-footer">
    <span>Conciergerie Liberty</span>
    <a href="/mentions-legales">Mentions légales</a>
    <a href="/confidentialite">Politique de confidentialité</a>
  </footer>`;
}

async function recordAnalytics(propertyId, eventName, eventValue = "", sessionId = "") {
  await run("INSERT INTO analytics_events (property_id, event_name, event_value, session_id, created_at) VALUES (?, ?, ?, ?, ?)", [
    propertyId || null,
    eventName,
    eventValue,
    sessionId,
    now(),
  ]);
}

function getTravelerSession(req, property) {
  const token = readToken(req, `liberty_guest_${property.slug}`);
  if (!token || token.type !== "guest" || token.propertyId !== property.id) return null;
  return token;
}

function isTravelerAuthenticated(req, property) {
  return Boolean(getTravelerSession(req, property));
}

function isAdminAuthenticated(req) {
  const token = readToken(req, "liberty_admin");
  return token && token.type === "admin";
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function readForm(req) {
  const body = await readBody(req);
  return Object.fromEntries(new URLSearchParams(body));
}

async function readJsonBody(req) {
  try {
    return JSON.parse(await readBody(req) || "{}");
  } catch {
    return {};
  }
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    ...securityHeaders(headers),
  });
  res.end(body);
}

function sendJson(res, status, body, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    ...securityHeaders(headers),
  });
  res.end(JSON.stringify(body));
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, securityHeaders({ Location: location, ...headers }));
  res.end();
}

function serveStatic(req, res, pathname) {
  const decoded = decodeURIComponent(pathname);
  const filePath = path.normalize(path.join(ROOT, decoded.replace(/^\/+/, "")));
  if (!filePath.startsWith(ROOT)) return send(res, 403, "Accès refusé");
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) return false;
  const ext = path.extname(filePath).toLowerCase();
  const types = {
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
  };
  res.writeHead(200, {
    "Content-Type": types[ext] || "application/octet-stream",
    "Cache-Control": "public, max-age=3600",
    ...securityHeaders(),
  });
  fs.createReadStream(filePath).pipe(res);
  return true;
}

function layout({ title, body, scripts = "", admin = false }) {
  return `<!doctype html>
<html lang="fr">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${escapeHtml(title)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="/public/styles.css" />
  </head>
  <body class="${admin ? "admin-body" : ""}">
    ${body}
    <div class="cookie-banner" data-cookie-banner hidden>
      <p>Conciergerie Liberty utilise des cookies strictement nécessaires pour sécuriser votre session et mesurer les usages essentiels du livret.</p>
      <button class="secondary-button compact" type="button" data-cookie-accept>Compris</button>
    </div>
    ${scripts}
    <script src="/public/traveler.js"></script>
  </body>
</html>`;
}

async function renderLanding() {
  const properties = await all("SELECT slug, name, city, cover_image FROM properties WHERE status = 'active' ORDER BY name");
  const cards = properties.map((property) => `
    <a class="property-card" href="/sejour/${escapeHtml(property.slug)}">
      <img src="${escapeHtml(property.cover_image)}" alt="" />
      <span>${escapeHtml(property.city)}</span>
      <strong>${escapeHtml(property.name)}</strong>
      <em>Ouvrir l'espace sécurisé</em>
    </a>`).join("");
  return layout({
    title: "Conciergerie Liberty | Espaces voyageurs",
    body: `<main class="landing">
      <section class="landing-hero">
        <p class="eyebrow">Groupe Liberty</p>
        <h1>Une structure dynamique pour tous les logements.</h1>
        <p>Chaque appartement dispose de son espace voyageurs personnalisé, alimenté par la base centralisée Liberty et préparé pour l'assistant IA.</p>
        <div class="landing-actions">
          <a class="premium-link" href="/sejour/appartement-cathedrale">Voir un espace voyageur <span>→</span></a>
        </div>
      </section>
      <section class="property-grid">${cards}</section>
      ${renderFooter()}
    </main>`,
  });
}

function renderLegalPage(kind) {
  const isPrivacy = kind === "privacy";
  return layout({
    title: isPrivacy ? "Politique de confidentialité | Conciergerie Liberty" : "Mentions légales | Conciergerie Liberty",
    body: `<main class="legal-page">
      <a class="brand" href="/"><span>Groupe Liberty</span><strong>Conciergerie Liberty</strong></a>
      <section>
        <p class="eyebrow">${isPrivacy ? "Confidentialité / RGPD" : "Mentions légales"}</p>
        <h1>${isPrivacy ? "Politique de confidentialité" : "Mentions légales"}</h1>
        ${isPrivacy ? `
          <p>Les espaces voyageurs Liberty collectent uniquement les informations nécessaires à l'exploitation du séjour, à la sécurité de l'accès, au traitement des demandes et, si le voyageur l'accepte, à la relation commerciale.</p>
          <h2>Données traitées</h2>
          <p>Logement consulté, demandes de service, messages envoyés à l'assistant, prénom, email, téléphone, dates de séjour et consentement marketing lorsque le formulaire CRM est rempli.</p>
          <h2>Cookies</h2>
          <p>Des cookies strictement nécessaires sont utilisés pour maintenir les sessions sécurisées. Les événements analytics internes mesurent les consultations, clics utiles et usages du livret afin d'améliorer la qualité de service.</p>
          <h2>Assistant IA</h2>
          <p>Les questions envoyées à l'assistant peuvent être transmises à OpenAI uniquement côté serveur lorsque la clé API du logement est configurée. Les clés API ne sont jamais exposées au navigateur.</p>
          <h2>Droits RGPD</h2>
          <p>Les voyageurs peuvent demander l'accès, la rectification ou la suppression de leurs données en contactant Conciergerie Liberty.</p>
        ` : `
          <p>Ce livret digital est édité pour Conciergerie Liberty afin de centraliser les informations d'accueil, d'exploitation locative et d'assistance voyageurs.</p>
          <h2>Éditeur</h2>
          <p>Conciergerie Liberty - Informations société à compléter avant mise en production : raison sociale, adresse, SIRET, responsable de publication, contact.</p>
          <h2>Hébergement</h2>
          <p>Informations hébergeur à compléter avant déploiement cPanel : nom, adresse, contact et pays d'hébergement.</p>
          <h2>Propriété intellectuelle</h2>
          <p>Les textes, visuels, interfaces et contenus Liberty sont destinés à l'usage de Conciergerie Liberty et de ses voyageurs autorisés.</p>
        `}
      </section>
      ${renderFooter()}
    </main>`,
  });
}

function renderPublicProperty(property) {
  const data = json(property.data_json, {});
  const direct = { ...(data.directBooking || {}), ...json(property.direct_booking_json, {}) };
  const schema = {
    "@context": "https://schema.org",
    "@type": "LodgingBusiness",
    name: property.name,
    address: property.address,
    image: property.cover_image,
    url: `${BASE_URL}/logement/${property.slug}`,
  };
  return layout({
    title: `${property.name} | Réservation Directe Liberty`,
    scripts: `<script type="application/ld+json">${safeJsonForScript(schema)}</script>`,
    body: `<main class="public-page">
      <section class="public-hero">
        <img src="${escapeHtml(property.cover_image)}" alt="" />
        <div>
          <p class="eyebrow">Réservation Directe Liberty</p>
          <h1>${escapeHtml(property.name)}</h1>
          <p>${escapeHtml(property.public_description || property.welcome)}</p>
          <div class="quick-actions">
            <a class="primary-button" href="/sejour/${escapeHtml(property.slug)}">Espace voyageurs</a>
            <a class="secondary-button" href="mailto:contact@conciergerie-liberty.fr?subject=${encodeURIComponent(`Réservation directe - ${property.name}`)}">${escapeHtml(direct.cta || "Demander une réservation")}</a>
          </div>
        </div>
      </section>
      <section class="content-section">
        <p class="eyebrow">Informations réservation</p>
        <h2>Structure prête pour le futur tunnel</h2>
        <div class="info-grid">
          ${card("Prix", direct.price || "Sur demande", "Tarif")}
          ${card("Disponibilités", direct.availability || "Calendrier à connecter", "Planning")}
          ${card("Équipements", (data.equipment?.items || []).map((item) => item.name).join(" · "), "Confort")}
        </div>
      </section>
      ${renderFooter()}
    </main>`,
  });
}

async function renderCityGuide(citySlug) {
  const cityName = citySlug.split("-").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
  const pois = await all("SELECT * FROM city_pois WHERE lower(city) = lower(?) ORDER BY type, title", [cityName]);
  const schema = {
    "@context": "https://schema.org",
    "@type": "TravelGuide",
    name: `Guide de ville Liberty - ${cityName}`,
    about: cityName,
  };
  return layout({
    title: `Guide de ville Liberty | ${cityName}`,
    scripts: `<script type="application/ld+json">${safeJsonForScript(schema)}</script>`,
    body: `<main class="public-page">
      <section class="landing-hero">
        <p class="eyebrow">City Guide Liberty</p>
        <h1>${escapeHtml(cityName)}</h1>
        <p>Guide SEO public réutilisable dans les livrets voyageurs Liberty : bonnes adresses, transports, parkings et points d'intérêt.</p>
      </section>
      <section class="content-section">
        <div class="poi-grid">${pois.map((poi) => poiCard(poi, `city_${poi.type}`)).join("") || "<p>Aucun point d'intérêt renseigné pour cette ville.</p>"}</div>
      </section>
      ${renderFooter()}
    </main>`,
  });
}

function renderGuestLogin(property, error = "") {
  return layout({
    title: `${property.name} | Accès voyageurs Liberty`,
    body: `<main class="secure-shell">
      <section class="gate-visual">
        <img src="${escapeHtml(property.cover_image)}" alt="Logement Liberty" />
        <div class="gate-brand"><span>Groupe Liberty</span><strong>${escapeHtml(property.name)}</strong></div>
      </section>
      <section class="gate-panel">
        <div class="gate-copy">
          <p class="eyebrow">Espace sécurisé voyageurs</p>
          <h1>Bienvenue chez Liberty.</h1>
          <p>${escapeHtml(property.welcome)}</p>
        </div>
        <form class="login-form" method="post" action="/sejour/${escapeHtml(property.slug)}/login">
          <label for="password">Mot de passe appartement</label>
          <div class="password-row">
            <input id="password" name="password" type="password" autocomplete="current-password" placeholder="Code transmis par Liberty" required />
            <button class="icon-button" type="button" data-toggle-password>Voir</button>
          </div>
          <p class="form-message">${escapeHtml(error)}</p>
          <button class="primary-button" type="submit">Entrer dans mon séjour</button>
        </form>
        <div class="security-note"><span></span><p>Accès propre à ce logement. Les informations sensibles restent protégées côté serveur.</p></div>
      </section>
    </main>`,
  });
}

function card(title, text, meta = "") {
  return `<article class="data-card">${meta ? `<span>${escapeHtml(meta)}</span>` : ""}<strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></article>`;
}

function poiCard(item, type) {
  const destination = item.address || item.title;
  const route = item.maps_url || mapsUrl(destination);
  const external = item.externalUrl || item.external_url || "";
  return `<article class="poi-card">
    <span>${escapeHtml(item.distance || "À proximité")}</span>
    <strong>${escapeHtml(item.title)}</strong>
    <p>${escapeHtml(item.description || item.text || "Sélection Liberty.")}</p>
    <div class="poi-actions">
      <a class="secondary-button compact" href="${escapeHtml(route)}" target="_blank" rel="noopener" data-track="${escapeHtml(type)}" data-track-value="${escapeHtml(item.title)}">Itinéraire</a>
      ${external ? `<a class="premium-link" href="${escapeHtml(external)}" target="_blank" rel="noopener" data-track="${escapeHtml(type)}_external" data-track-value="${escapeHtml(item.title)}">Lien utile <span>→</span></a>` : ""}
    </div>
  </article>`;
}

function uniqueCards(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = String(item.title || "").toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function renderTraveler(property, req) {
  const p = publicProperty(property);
  const d = p.data;
  const equipment = d.equipment?.items || [];
  const services = d.services || [];
  const guide = d.housingGuide || [];
  const assistance = d.assistance || [];
  const city = d.city || {};
  const guides = city.guides || [];
  const wifi = normalizeWifi(d, property);
  const wifiPayload = `WIFI:T:${wifi.encryption || "WPA"};S:${wifi.ssid};P:${wifi.password};;`;
  const wifiQr = wifi.ssid ? await QRCode.toString(wifiPayload, { type: "svg", margin: 1, width: 180 }) : "";
  const itineraryUrl = mapsUrl(p.address, p.gps);
  const appleUrl = appleMapsUrl(p.address, p.gps);
  const sharedPois = await all("SELECT * FROM city_pois WHERE lower(city) = lower(?) ORDER BY type, title", [p.city]);
  const sharedBonsPlans = sharedPois.filter((poi) => !["transport", "parking"].includes(poi.type));
  const sharedTransports = sharedPois.filter((poi) => ["transport", "parking"].includes(poi.type));
  const bonsPlans = uniqueCards([
    ...(city.bonsPlans || (city.restaurants || []).map((title) => ({ title, description: "Adresse recommandée par Liberty.", distance: "À proximité", address: `${title}, ${p.city}`, externalUrl: "" }))),
    ...sharedBonsPlans,
  ]);
  const transports = uniqueCards([
    ...(city.transports || (city.transport || []).map((title) => ({ title, description: "Option de transport utile pour votre séjour.", distance: "À vérifier", address: `${title}, ${p.city}`, externalUrl: "" }))),
    ...sharedTransports,
  ]);
  const session = getTravelerSession(req, property) || {};
  await recordAnalytics(property.id, "booklet_view", "", session.sessionId || "");

  return layout({
    title: `${p.name} | Espace voyageurs Liberty`,
    body: `<div class="app-shell" data-slug="${escapeHtml(p.slug)}">
      <aside class="side-nav">
        <a class="brand" href="#accueil"><span>Groupe Liberty</span><strong>Conciergerie Liberty</strong></a>
        <nav>
          <a href="#mon-sejour">Mon Séjour</a>
          <a href="#logement">Le Logement</a>
          <a href="#ville">Découvrir la Ville</a>
          <a href="#services">Services Liberty</a>
          <a href="#assistant">Assistant IA Liberty</a>
        </nav>
        <form method="post" action="/sejour/${escapeHtml(p.slug)}/logout">
          <button class="secondary-button compact" type="submit">Verrouiller</button>
        </form>
      </aside>

      <main class="traveler-main">
        <section class="traveler-hero" id="accueil">
          <img src="${escapeHtml(p.coverImage)}" alt="" />
          <div class="hero-copy">
            <p class="eyebrow">Espace voyageurs sécurisé</p>
            <h1>${escapeHtml(p.name)}</h1>
            <p>${escapeHtml(p.welcome)}</p>
            <div class="quick-actions">
              <a class="primary-button" href="#arrivee">Arrivée</a>
              <a class="secondary-button" href="#wifi">Wi-Fi</a>
              <a class="premium-link" href="#assistant">Assistant IA <span>→</span></a>
            </div>
          </div>
        </section>

        <section class="metric-row">
          <div><span>${escapeHtml(p.city)}</span><p>Destination</p></div>
          <div><span>${escapeHtml(d.arrival?.checkin || "16h")}</span><p>Check-in</p></div>
          <div><span>${escapeHtml(d.departure?.checkout || "10h")}</span><p>Check-out</p></div>
        </section>

        <section class="content-section" id="mon-sejour">
          <p class="eyebrow">Mon Séjour</p>
          <h2>Informations essentielles</h2>
          <div class="info-grid">
            ${card("Voyageur", d.stay?.guestName || "À personnaliser", "Accueil")}
            ${card("Dates", d.stay?.dates || "À personnaliser", "Réservation")}
            ${card("Code d'accès", d.stay?.accessCode || "Transmis avant arrivée", "Sécurité")}
          </div>
          <div class="notice-list">${(d.stay?.messages || []).map((message) => `<p>${escapeHtml(message)}</p>`).join("")}</div>
          <form class="crm-form" data-crm-form>
            <div>
              <span class="panel-label">Recevoir les avantages Liberty</span>
              <p>Recevez votre code fidélité, les offres de réservation directe et les attentions utiles pour vos prochains séjours.</p>
            </div>
            <input name="firstName" placeholder="Prénom" autocomplete="given-name" />
            <input name="email" type="email" placeholder="Email" autocomplete="email" />
            <input name="phone" placeholder="Téléphone" autocomplete="tel" />
            <input name="stayDates" placeholder="Dates de séjour" value="${escapeHtml(d.stay?.dates || "")}" />
            <label class="consent-row"><input name="marketingConsent" type="checkbox" value="1" /> J'accepte de recevoir les offres et communications de Conciergerie Liberty.</label>
            <button class="secondary-button compact" type="submit">Enregistrer mes informations</button>
            <p class="form-message" data-crm-status></p>
          </form>
        </section>

        <section class="content-section" id="arrivee">
          <p class="eyebrow">Arrivée</p>
          <h2>Arriver sans contacter Liberty</h2>
          <div class="map-panel">
            <div>
              <span class="panel-label">Adresse du logement</span>
              <strong>${escapeHtml(p.address)}</strong>
              <p>${escapeHtml(p.gps)}</p>
            </div>
            <div class="map-actions">
              <a class="primary-button" href="${escapeHtml(itineraryUrl)}" target="_blank" rel="noopener" data-track="itinerary" data-track-value="google_maps">Ouvrir l'itinéraire</a>
              <a class="secondary-button" href="${escapeHtml(appleUrl)}" target="_blank" rel="noopener" data-track="itinerary" data-track-value="apple_maps">Apple Plans</a>
            </div>
          </div>
          <div class="info-grid">
            ${card("Adresse", p.address, "Localisation")}
            ${card("GPS", p.gps, "Coordonnées")}
            ${card("Parking", d.arrival?.parking, "Accès")}
            ${card("Boîte à clés", d.arrival?.keybox, "Remise des clés")}
            ${card("Check-in", d.arrival?.checkin, "Horaire")}
            ${card("Tutoriel vidéo", d.arrival?.video, "Support")}
          </div>
        </section>

        <section class="content-section" id="depart">
          <p class="eyebrow">Départ</p>
          <h2>Départ et remise en exploitation</h2>
          <div class="split-panel">
            <div>
              <span class="panel-label">Heure de départ</span>
              <strong>${escapeHtml(d.departure?.checkout)}</strong>
              <p>${escapeHtml(d.departure?.cleaning)}</p>
            </div>
            <ul>${(d.departure?.checklist || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
          </div>
        </section>

        <section class="content-section" id="wifi">
          <p class="eyebrow">Wi-Fi & Équipements</p>
          <h2>Confort du logement</h2>
          <div class="wifi-panel" data-wifi-panel>
            <div class="wifi-card">
              <span>Réseau</span><strong>${escapeHtml(wifi.ssid)}</strong>
              <span>Mot de passe</span><strong>${escapeHtml(wifi.password)}</strong>
            </div>
            <div class="wifi-qr" aria-label="QR code Wi-Fi">${wifiQr}</div>
          </div>
          <div class="info-grid">${equipment.map((item) => card(item.name, item.details, "Équipement")).join("")}</div>
        </section>

        <section class="content-section" id="logement">
          <p class="eyebrow">Guide du Logement</p>
          <h2>Fonctionnement, photos et tutoriels</h2>
          <div class="guide-list">${guide.map((item) => `<article><span>${escapeHtml(item.media)}</span><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.text)}</p></article>`).join("")}</div>
        </section>

        <section class="content-section contrast-section" id="assistance">
          <p class="eyebrow">Assistance</p>
          <h2>Dépannage rapide</h2>
          <div class="assistance-grid">${assistance.map((item) => card(item.title, item.text, "Procédure")).join("")}</div>
        </section>

        <section class="content-section" id="ville">
          <p class="eyebrow">Découvrir la Ville</p>
          <h2>Bons Plans Liberty</h2>
          <div class="poi-grid">${bonsPlans.map((item) => poiCard(item, "poi")).join("")}</div>
        </section>

        <section class="content-section" id="transports">
          <p class="eyebrow">Transport</p>
          <h2>Venir, repartir et se déplacer</h2>
          <div class="poi-grid">${transports.map((item) => poiCard(item, "transport")).join("")}</div>
        </section>

        <section class="content-section" id="city-guide">
          <p class="eyebrow">City Guide Liberty</p>
          <h2>Guides de séjour</h2>
          <div class="editorial-grid">
            ${card("Réservation d'Activités", (city.activities || []).join(" · "), "Expériences")}
            ${card("Restaurants", (city.restaurants || []).join(" · "), "Sélection")}
            ${card("Lieux touristiques", (city.highlights || []).join(" · "), "Incontournables")}
          </div>
          <div class="guide-list">${guides.map((item) => `<article><span>City Guide Liberty</span><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.text)}</p></article>`).join("")}</div>
        </section>

        <section class="content-section" id="services">
          <p class="eyebrow">Services Liberty</p>
          <h2>Options, réservations et fidélité</h2>
          <div class="service-grid">${services.map((item) => `<article class="service-card"><span>${escapeHtml(item.price)}</span><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.text)}</p><button class="secondary-button compact" data-service="${escapeHtml(item.title)}">Demander</button></article>`).join("")}</div>
          <div class="business-band">
            ${card(d.directBooking?.title, `${d.directBooking?.text} Code : ${d.directBooking?.promo}`, "Réservation directe")}
            ${card("Programme Fidélité", (d.loyalty?.benefits || []).join(" · "), "Avantages VIP")}
          </div>
        </section>

        <section class="content-section service-center" id="centre-services">
          <p class="eyebrow">Centre de Services Liberty</p>
          <h2>Créer une demande sans WhatsApp</h2>
          <form class="request-form" data-request-form>
            <select name="type" aria-label="Type de demande">
              <option>Signaler un problème</option>
              <option>Demander un ménage</option>
              <option>Demander du linge</option>
              <option>Demander une intervention</option>
              <option>Réserver une option payante</option>
            </select>
            <input name="guestName" placeholder="Nom du voyageur" />
            <textarea name="message" placeholder="Décrivez votre demande" required></textarea>
            <button class="primary-button" type="submit">Envoyer à Liberty</button>
            <p class="form-message" data-request-status></p>
          </form>
        </section>

        <section class="content-section assistant-section" id="assistant">
          <p class="eyebrow">Mon Assistant IA Liberty</p>
          <h2>Questions logement, ville et dépannage</h2>
          <p class="assistant-note">L'assistant répond uniquement avec les informations disponibles dans ce livret. Limite de session : ${Number(property.ai_session_limit || 20)} messages.</p>
          <div class="chat-shell">
            <div class="chat-feed" data-chat-feed>
              <div class="chat-message assistant">Bonjour, je suis l'Assistant IA Liberty de ${escapeHtml(p.name)}. Comment puis-je vous aider ?</div>
            </div>
            <form class="chat-form" data-chat-form>
              <input name="message" placeholder="Exemple : où se trouve la boîte à clés ?" autocomplete="off" required />
              <button class="primary-button compact" type="submit">Envoyer</button>
            </form>
          </div>
        </section>
      </main>
    </div>
    ${renderFooter()}`,
  });
}

function renderAdminLogin(error = "") {
  return layout({
    title: "Administration Liberty",
    admin: true,
    body: `<main class="admin-login">
      <section>
        <p class="eyebrow">Administration Liberty</p>
        <h1>Pilotage des logements</h1>
        <p>Connectez-vous pour modifier les espaces voyageurs, URLs, mots de passe, consignes IA et modules Liberty.</p>
        <form class="login-form" method="post" action="/admin/login">
          ${csrfField("admin")}
          <label for="password">Mot de passe administrateur</label>
          <input id="password" name="password" type="password" required />
          <p class="form-message">${escapeHtml(error)}</p>
          <button class="primary-button" type="submit">Accéder au panneau</button>
        </form>
      </section>
    </main>`,
  });
}

async function renderAdmin(req, message = "") {
  const properties = await all("SELECT * FROM properties ORDER BY name");
  const requests = await all(`SELECT service_requests.*, properties.name AS property_name
    FROM service_requests JOIN properties ON properties.id = service_requests.property_id
    ORDER BY service_requests.created_at DESC LIMIT 12`);
  const analytics = await all(`SELECT event_name, COUNT(*) AS count FROM analytics_events GROUP BY event_name ORDER BY event_name`);
  const analyticsMap = Object.fromEntries(analytics.map((event) => [event.event_name, event.count]));
  const statCards = [
    ["Consultations", analyticsMap.booklet_view || 0],
    ["Clics itinéraire", analyticsMap.itinerary || 0],
    ["Affichages Wi-Fi", analyticsMap.wifi_view || 0],
    ["Questions IA", analyticsMap.ai_question || 0],
    ["Formulaires CRM", analyticsMap.crm_submit || 0],
    ["Clics bons plans", (analyticsMap.poi || 0) + (analyticsMap.poi_external || 0)],
    ["Clics transports", (analyticsMap.transport || 0) + (analyticsMap.transport_external || 0)],
    ["Upsells demandés", analyticsMap.service_request || 0],
  ].map(([label, value]) => `<article class="stat-card"><span>${escapeHtml(value)}</span><p>${escapeHtml(label)}</p></article>`).join("");
  const rows = properties.map((property) => `
    <tr>
      <td><strong>${escapeHtml(property.name)}</strong><span>${escapeHtml(property.city)}</span></td>
      <td><a href="/sejour/${escapeHtml(property.slug)}" target="_blank">/sejour/${escapeHtml(property.slug)}</a></td>
      <td>${escapeHtml(property.status)}</td>
      <td><a class="secondary-button compact" href="/admin/logements/${property.id}">Modifier</a></td>
    </tr>`).join("");
  const requestRows = requests.map((request) => `
    <tr>
      <td>${escapeHtml(request.property_name)}</td>
      <td>${escapeHtml(request.type)}</td>
      <td>${escapeHtml(request.message)}</td>
      <td>${escapeHtml(request.status)}</td>
    </tr>`).join("");
  return layout({
    title: "Administration Liberty | Logements",
    admin: true,
    body: `<div class="admin-shell">
      <header class="admin-topbar">
        <a class="brand" href="/admin"><span>Groupe Liberty</span><strong>Administration</strong></a>
        <form method="post" action="/admin/logout">${csrfField("admin")}<button class="secondary-button compact" type="submit">Déconnexion</button></form>
      </header>
      <main class="admin-main">
        <section class="admin-heading">
          <p class="eyebrow">Base centralisée</p>
          <h1>Logements Liberty</h1>
          <p>Une seule structure technique pilote les espaces voyageurs, mots de passe, consignes IA, services et demandes.</p>
          ${message ? `<p class="success-message">${escapeHtml(message)}</p>` : ""}
        </section>
        <section class="admin-panel">
          <div class="panel-title"><h2>Analytics</h2><p>Mesure évolutive des messages évités, usages clés et opportunités d'upsell.</p></div>
          <div class="stats-grid">${statCards}</div>
        </section>
        <section class="admin-panel">
          <div class="panel-title"><h2>Créer un logement</h2><p>L'URL unique est générée depuis le nom si le slug est vide.</p></div>
          <form class="admin-form grid-form" method="post" action="/admin/logements">
            ${csrfField("admin")}
            <input name="name" placeholder="Nom du logement" required />
            <input name="city" placeholder="Ville" required />
            <input name="slug" placeholder="slug-url-optionnel" />
            <input name="password" placeholder="Mot de passe voyageur" required />
            <button class="primary-button" type="submit">Créer l'espace</button>
          </form>
        </section>
        <section class="admin-panel">
          <div class="panel-title"><h2>Espaces voyageurs</h2><p>URLs prêtes pour le modèle liberty.fr/sejour/nom-du-logement.</p></div>
          <div class="table-wrap"><table><thead><tr><th>Logement</th><th>URL unique</th><th>Statut</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
        </section>
        <section class="admin-panel">
          <div class="panel-title"><h2>Centre de Services</h2><p>Demandes voyageurs centralisées hors WhatsApp.</p></div>
          <div class="table-wrap"><table><thead><tr><th>Logement</th><th>Type</th><th>Message</th><th>Statut</th></tr></thead><tbody>${requestRows || `<tr><td colspan="4">Aucune demande pour le moment.</td></tr>`}</tbody></table></div>
        </section>
      </main>
    </div>`,
  });
}

function renderEditProperty(property, message = "") {
  const parsedData = json(property.data_json, {});
  const data = JSON.stringify(parsedData, null, 2);
  const wifi = normalizeWifi(parsedData, property);
  const city = parsedData.city || {};
  const directBooking = json(property.direct_booking_json, parsedData.directBooking || {});
  return layout({
    title: `Modifier ${property.name} | Administration Liberty`,
    admin: true,
    body: `<div class="admin-shell">
      <header class="admin-topbar">
        <a class="brand" href="/admin"><span>Groupe Liberty</span><strong>Administration</strong></a>
        <a class="secondary-button compact" href="/sejour/${escapeHtml(property.slug)}" target="_blank">Voir l'espace</a>
      </header>
      <main class="admin-main narrow">
        <section class="admin-heading">
          <p class="eyebrow">Modifier un logement</p>
          <h1>${escapeHtml(property.name)}</h1>
          <p>Modifiez les informations opérationnelles sans toucher au code. Les données alimentent automatiquement l'espace voyageur et l'assistant IA.</p>
          ${message ? `<p class="success-message">${escapeHtml(message)}</p>` : ""}
        </section>
        <form class="admin-form edit-form" method="post" action="/admin/logements/${property.id}">
          ${csrfField("admin")}
          <label>Nom<input name="name" value="${escapeHtml(property.name)}" required /></label>
          <label>Slug URL<input name="slug" value="${escapeHtml(property.slug)}" required /></label>
          <label>Ville<input name="city" value="${escapeHtml(property.city)}" /></label>
          <label>Image principale<input name="cover_image" value="${escapeHtml(property.cover_image)}" /></label>
          <label>Adresse<input name="address" value="${escapeHtml(property.address)}" /></label>
          <label>GPS<input name="gps" value="${escapeHtml(property.gps)}" /></label>
          <label>Message de bienvenue<textarea name="welcome">${escapeHtml(property.welcome)}</textarea></label>
          <div class="admin-fieldset">
            <h2>Arrivée</h2>
            <label>Parking<textarea name="arrival_parking">${escapeHtml(parsedData.arrival?.parking || "")}</textarea></label>
            <label>Boîte à clés<textarea name="arrival_keybox">${escapeHtml(parsedData.arrival?.keybox || "")}</textarea></label>
            <label>Check-in<input name="arrival_checkin" value="${escapeHtml(parsedData.arrival?.checkin || "")}" /></label>
            <label>Tutoriel vidéo<input name="arrival_video" value="${escapeHtml(parsedData.arrival?.video || "")}" /></label>
          </div>
          <div class="admin-fieldset">
            <h2>Départ & règles</h2>
            <label>Heure de départ<input name="departure_checkout" value="${escapeHtml(parsedData.departure?.checkout || "")}" /></label>
            <label>Consignes ménage<textarea name="departure_cleaning">${escapeHtml(parsedData.departure?.cleaning || "")}</textarea></label>
            <label>Checklist départ<textarea name="departure_checklist">${escapeHtml(listToTextarea(parsedData.departure?.checklist))}</textarea></label>
            <label>Règles du logement<textarea name="rules">${escapeHtml(listToTextarea(parsedData.rules))}</textarea></label>
          </div>
          <div class="admin-fieldset">
            <h2>Wi-Fi & équipements</h2>
            <label>Wi-Fi SSID<input name="wifi_ssid" value="${escapeHtml(wifi.ssid)}" /></label>
            <label>Mot de passe Wi-Fi<input name="wifi_password" value="${escapeHtml(wifi.password)}" /></label>
            <label>Équipements JSON<textarea name="equipment_items" rows="7">${escapeHtml(JSON.stringify(parsedData.equipment?.items || [], null, 2))}</textarea></label>
          </div>
          <div class="admin-fieldset">
            <h2>Bons plans, transports, contacts</h2>
            <label>Bons plans (titre | description | distance | adresse | lien)<textarea name="bons_plans" rows="6">${escapeHtml(cardsToTextarea(city.bonsPlans))}</textarea></label>
            <label>Transports (titre | description | distance | adresse | lien)<textarea name="transports" rows="6">${escapeHtml(cardsToTextarea(city.transports))}</textarea></label>
            <label>Contacts utiles JSON<textarea name="contacts" rows="5">${escapeHtml(JSON.stringify(parsedData.contacts || {}, null, 2))}</textarea></label>
          </div>
          <div class="admin-fieldset">
            <h2>Assistant IA</h2>
            <label>Limite IA par jour<input name="ai_daily_limit" type="number" min="1" value="${escapeHtml(property.ai_daily_limit || 80)}" /></label>
            <label>Limite IA par session<input name="ai_session_limit" type="number" min="1" value="${escapeHtml(property.ai_session_limit || 20)}" /></label>
            <label>Longueur question max<input name="ai_max_input_chars" type="number" min="100" value="${escapeHtml(property.ai_max_input_chars || 700)}" /></label>
          </div>
          <div class="admin-fieldset">
            <h2>Réservation directe</h2>
            <label>Description publique<textarea name="public_description">${escapeHtml(property.public_description || property.welcome)}</textarea></label>
            <label>Prix<input name="direct_price" value="${escapeHtml(directBooking.price || parsedData.directBooking?.price || "")}" /></label>
            <label>Disponibilités<input name="direct_availability" value="${escapeHtml(directBooking.availability || parsedData.directBooking?.availability || "")}" /></label>
            <label>CTA réservation<input name="direct_cta" value="${escapeHtml(directBooking.cta || parsedData.directBooking?.cta || "")}" /></label>
          </div>
          <label>Nouveau mot de passe voyageur<input name="password" placeholder="Laisser vide pour conserver" /></label>
          <label>Clé API OpenAI du logement<input name="openai_api_key" value="${property.openai_api_key ? "********" : ""}" placeholder="sk-..." /></label>
          <label>Modèle OpenAI<input name="openai_model" value="${escapeHtml(property.openai_model)}" /></label>
          <label>Instructions Assistant IA<textarea name="ai_instructions" rows="7">${escapeHtml(property.ai_instructions)}</textarea></label>
          <label>Données opérationnelles JSON<textarea name="data_json" rows="22" spellcheck="false">${escapeHtml(data)}</textarea></label>
          <div class="form-actions">
            <button class="primary-button" type="submit">Enregistrer</button>
            <a class="secondary-button" href="/admin">Retour</a>
          </div>
        </form>
      </main>
    </div>`,
  });
}

function buildAssistantContext(property) {
  const data = json(property.data_json, {});
  return [
    `Logement: ${property.name}`,
    `Ville: ${property.city}`,
    `Adresse: ${property.address}`,
    `GPS: ${property.gps}`,
    `Bienvenue: ${property.welcome}`,
    `Données opérationnelles: ${JSON.stringify(data)}`,
  ].join("\n");
}

function localAssistantReply(property, message) {
  const haystack = buildAssistantContext(property).toLowerCase();
  const lower = message.toLowerCase();
  const data = json(property.data_json, {});
  if (lower.includes("wifi") || lower.includes("wi-fi")) {
    return `Le réseau Wi-Fi est ${data.equipment?.wifi?.network || "à compléter"} et le mot de passe est ${data.equipment?.wifi?.password || "à compléter"}.`;
  }
  if (lower.includes("clé") || lower.includes("cle") || lower.includes("boîte")) {
    return data.arrival?.keybox || "La procédure de remise des clés doit être complétée par Liberty.";
  }
  if (lower.includes("parking")) return data.arrival?.parking || "Le parking doit être précisé par Liberty.";
  if (lower.includes("départ") || lower.includes("check-out")) return data.departure?.checkout || "Le départ est à confirmer.";
  if (lower.includes("adresse")) return `${property.address} (${property.gps}).`;
  if (haystack.includes(lower.slice(0, 16))) {
    return "J'ai trouvé des informations liées à votre question dans le livret. Consultez les sections Arrivée, Wi-Fi & Équipements ou Assistance pour le détail opérationnel.";
  }
  return "Je peux répondre aux questions sur l'arrivée, le Wi-Fi, les équipements, le départ, les bons plans et le dépannage. Si votre demande nécessite une intervention, créez une demande dans le Centre de Services Liberty.";
}

async function callOpenAI(property, message) {
  if (!property.openai_api_key || property.openai_api_key === "********") {
    return localAssistantReply(property, message);
  }
  const instructions = `${property.ai_instructions}

Règles obligatoires :
- Répondre uniquement avec les informations présentes dans le contexte du logement ci-dessous.
- Ne jamais inventer un code, une adresse, un horaire, un prix, une règle ou un contact.
- Si l'information n'est pas disponible, dire clairement qu'elle n'est pas présente dans le livret et proposer le Centre de Services Liberty.
- Réponse courte, rassurante et opérationnelle.

Contexte logement Liberty:
${buildAssistantContext(property)}`;
  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${property.openai_api_key}`,
    },
    body: JSON.stringify({
      model: property.openai_model || DEFAULT_OPENAI_MODEL,
      instructions,
      input: message,
      store: false,
      max_output_tokens: 450,
    }),
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result?.error?.message || "Erreur OpenAI");
  }
  return result.output_text || localAssistantReply(property, message);
}

async function handleRequest(req, res) {
  const url = new URL(req.url, BASE_URL);
  const pathname = decodeURIComponent(url.pathname);

  if (shouldRedirectHttps(req)) {
    return redirect(res, `https://${req.headers.host}${req.url}`);
  }

  if (pathname.startsWith("/assets/") || pathname.startsWith("/public/")) {
    if (serveStatic(req, res, pathname)) return;
  }

  if (req.method === "GET" && pathname === "/") return send(res, 200, await renderLanding());
  if (req.method === "GET" && pathname === "/mentions-legales") return send(res, 200, renderLegalPage("legal"));
  if (req.method === "GET" && pathname === "/confidentialite") return send(res, 200, renderLegalPage("privacy"));

  const publicPropertyMatch = pathname.match(/^\/logement\/([^/]+)$/);
  if (publicPropertyMatch && req.method === "GET") {
    const property = await propertyBySlug(publicPropertyMatch[1]);
    if (!property) return send(res, 404, "Logement introuvable");
    return send(res, 200, renderPublicProperty(property));
  }

  const cityGuideMatch = pathname.match(/^\/guide\/([^/]+)$/);
  if (cityGuideMatch && req.method === "GET") {
    return send(res, 200, await renderCityGuide(cityGuideMatch[1]));
  }

  if (pathname === "/admin" && req.method === "GET") {
    if (!isAdminAuthenticated(req)) return send(res, 200, renderAdminLogin());
    return send(res, 200, await renderAdmin(req, url.searchParams.get("message") || ""));
  }
  if (pathname === "/admin/login" && req.method === "POST") {
    const form = await readForm(req);
    if (!verifyCsrf(form.csrf, "admin")) return send(res, 403, renderAdminLogin("Session expirée. Rechargez la page."));
    if (isAdminRateLimited(req)) return send(res, 429, renderAdminLogin("Trop de tentatives. Réessayez dans quelques minutes."));
    const stored = (await get("SELECT value FROM admin_settings WHERE `key` = ?", ["admin_password_hash"])).value;
    if (!verifyPassword(form.password || "", stored)) {
      recordAdminLoginAttempt(req, false);
      return send(res, 401, renderAdminLogin("Mot de passe incorrect."));
    }
    recordAdminLoginAttempt(req, true);
    return redirect(res, "/admin", { "Set-Cookie": cookie(req, "liberty_admin", makeToken({ type: "admin" })) });
  }
  if (pathname === "/admin/logout" && req.method === "POST") {
    const form = await readForm(req);
    if (!verifyCsrf(form.csrf, "admin")) return redirect(res, "/admin");
    return redirect(res, "/admin", { "Set-Cookie": clearCookie("liberty_admin") });
  }
  if (pathname === "/admin/logements" && req.method === "POST") {
    if (!isAdminAuthenticated(req)) return redirect(res, "/admin");
    const form = await readForm(req);
    if (!verifyCsrf(form.csrf, "admin")) return send(res, 403, await renderAdmin(req, "Session expirée. Rechargez la page."));
    const slug = slugify(form.slug || form.name);
    const data = defaultPropertyData();
    await run(
      `INSERT INTO properties (slug, name, city, traveler_password_hash, welcome, data_json, ai_instructions, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [slug, form.name, form.city, hashPassword(form.password), `Bienvenue dans votre espace voyageurs ${form.name}.`, JSON.stringify(data), "Instructions Assistant IA Liberty à compléter avant déploiement.", now(), now()]
    );
    return redirect(res, "/admin?message=Logement créé");
  }
  const editMatch = pathname.match(/^\/admin\/logements\/(\d+)$/);
  if (editMatch && !isAdminAuthenticated(req)) return redirect(res, "/admin");
  if (editMatch && req.method === "GET") {
    const property = await get("SELECT * FROM properties WHERE id = ?", [Number(editMatch[1])]);
    if (!property) return send(res, 404, "Logement introuvable");
    return send(res, 200, renderEditProperty(property, url.searchParams.get("message") || ""));
  }
  if (editMatch && req.method === "POST") {
    const property = await get("SELECT * FROM properties WHERE id = ?", [Number(editMatch[1])]);
    if (!property) return send(res, 404, "Logement introuvable");
    const form = await readForm(req);
    if (!verifyCsrf(form.csrf, "admin")) return send(res, 403, renderEditProperty(property, "Session expirée. Rechargez la page."));
    let parsed;
    try {
      parsed = JSON.parse(form.data_json || "{}");
      parsed.arrival = {
        ...(parsed.arrival || {}),
        parking: form.arrival_parking || "",
        keybox: form.arrival_keybox || "",
        checkin: form.arrival_checkin || "",
        video: form.arrival_video || "",
      };
      parsed.departure = {
        ...(parsed.departure || {}),
        checkout: form.departure_checkout || "",
        cleaning: form.departure_cleaning || "",
        checklist: textareaToList(form.departure_checklist),
      };
      parsed.rules = textareaToList(form.rules);
      parsed.equipment = parsed.equipment || {};
      parsed.equipment.wifi = { ...(parsed.equipment.wifi || {}), network: form.wifi_ssid || "", ssid: form.wifi_ssid || "", password: form.wifi_password || "" };
      parsed.wifi_ssid = form.wifi_ssid || "";
      parsed.wifi_password = form.wifi_password || "";
      try {
        parsed.equipment.items = JSON.parse(form.equipment_items || "[]");
      } catch {
        return send(res, 400, renderEditProperty(property, "Le JSON équipements est invalide."));
      }
      parsed.city = parsed.city || {};
      parsed.city.bonsPlans = textareaToCards(form.bons_plans);
      parsed.city.transports = textareaToCards(form.transports);
      try {
        parsed.contacts = JSON.parse(form.contacts || "{}");
      } catch {
        return send(res, 400, renderEditProperty(property, "Le JSON contacts est invalide."));
      }
      parsed.directBooking = {
        ...(parsed.directBooking || {}),
        price: form.direct_price || "",
        availability: form.direct_availability || "",
        cta: form.direct_cta || "",
      };
    } catch {
      return send(res, 400, renderEditProperty(property, "Le JSON opérationnel est invalide."));
    }
    const passwordHash = form.password ? hashPassword(form.password) : property.traveler_password_hash;
    const apiKey = form.openai_api_key && form.openai_api_key !== "********" ? form.openai_api_key : property.openai_api_key;
    const directBooking = {
      price: form.direct_price || "",
      availability: form.direct_availability || "",
      cta: form.direct_cta || "",
      description: form.public_description || "",
    };
    await run(
      `UPDATE properties SET slug=?, name=?, city=?, cover_image=?, address=?, gps=?, welcome=?, traveler_password_hash=?,
       openai_api_key=?, openai_model=?, ai_instructions=?, wifi_ssid=?, wifi_password=?, ai_daily_limit=?, ai_session_limit=?, ai_max_input_chars=?,
       public_description=?, direct_booking_json=?, data_json=?, updated_at=? WHERE id=?`,
      [
        slugify(form.slug),
        form.name,
        form.city,
        form.cover_image,
        form.address,
        form.gps,
        form.welcome,
        passwordHash,
        apiKey,
        form.openai_model || DEFAULT_OPENAI_MODEL,
        form.ai_instructions,
        form.wifi_ssid || "",
        form.wifi_password || "",
        Number(form.ai_daily_limit || 80),
        Number(form.ai_session_limit || 20),
        Number(form.ai_max_input_chars || 700),
        form.public_description || "",
        JSON.stringify(directBooking),
        JSON.stringify(parsed),
        now(),
        property.id,
      ]
    );
    return redirect(res, `/admin/logements/${property.id}?message=Modifications enregistrées`);
  }

  const stayMatch = pathname.match(/^\/sejour\/([^/]+)(?:\/(login|logout))?$/);
  if (stayMatch) {
    const property = await propertyBySlug(stayMatch[1]);
    if (!property) return send(res, 404, "Espace voyageur introuvable");
    const action = stayMatch[2];
    if (action === "login" && req.method === "POST") {
      const form = await readForm(req);
      if (!verifyPassword(form.password || "", property.traveler_password_hash)) {
        return send(res, 401, renderGuestLogin(property, "Mot de passe incorrect pour ce logement."));
      }
      const sessionId = crypto.randomBytes(12).toString("hex");
      return redirect(res, `/sejour/${property.slug}`, {
        "Set-Cookie": cookie(req, `liberty_guest_${property.slug}`, makeToken({ type: "guest", propertyId: property.id, sessionId })),
      });
    }
    if (action === "logout" && req.method === "POST") {
      return redirect(res, `/sejour/${property.slug}`, { "Set-Cookie": clearCookie(`liberty_guest_${property.slug}`) });
    }
    if (!isTravelerAuthenticated(req, property)) return send(res, 200, renderGuestLogin(property));
    return send(res, 200, await renderTraveler(property, req));
  }

  const requestMatch = pathname.match(/^\/api\/service-request\/([^/]+)$/);
  if (requestMatch && req.method === "POST") {
    const property = await propertyBySlug(requestMatch[1]);
    const session = property ? getTravelerSession(req, property) : null;
    if (!property || !session) return sendJson(res, 403, { error: "Accès refusé" });
    const body = await readJsonBody(req);
    await run("INSERT INTO service_requests (property_id, type, guest_name, message, created_at) VALUES (?, ?, ?, ?, ?)", [
      property.id,
      body.type || "Demande voyageur",
      body.guestName || "",
      body.message || "",
      now(),
    ]);
    await recordAnalytics(property.id, "service_request", body.type || "Demande voyageur", session.sessionId || "");
    return sendJson(res, 200, { ok: true, message: "Votre demande a été transmise au Centre de Services Liberty." });
  }

  const crmMatch = pathname.match(/^\/api\/crm\/([^/]+)$/);
  if (crmMatch && req.method === "POST") {
    const property = await propertyBySlug(crmMatch[1]);
    const session = property ? getTravelerSession(req, property) : null;
    if (!property || !session) return sendJson(res, 403, { error: "Accès refusé" });
    const body = await readJsonBody(req);
    if (!body.email && !body.phone) return sendJson(res, 400, { error: "Email ou téléphone requis." });
    await run(
      "INSERT INTO crm_leads (property_id, first_name, email, phone, stay_dates, marketing_consent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [property.id, body.firstName || "", body.email || "", body.phone || "", body.stayDates || "", body.marketingConsent ? 1 : 0, now()]
    );
    await recordAnalytics(property.id, "crm_submit", body.marketingConsent ? "marketing_yes" : "marketing_no", session.sessionId || "");
    return sendJson(res, 200, { ok: true, message: "Merci, vos informations ont été enregistrées." });
  }

  const analyticsMatch = pathname.match(/^\/api\/analytics\/([^/]+)$/);
  if (analyticsMatch && req.method === "POST") {
    const property = await propertyBySlug(analyticsMatch[1]);
    const session = property ? getTravelerSession(req, property) : null;
    if (!property || !session) return sendJson(res, 403, { error: "Accès refusé" });
    const body = await readJsonBody(req);
    await recordAnalytics(property.id, String(body.event || "event").slice(0, 80), String(body.value || "").slice(0, 160), session.sessionId || "");
    return sendJson(res, 200, { ok: true });
  }

  const chatMatch = pathname.match(/^\/api\/chat\/([^/]+)$/);
  if (chatMatch && req.method === "POST") {
    const property = await propertyBySlug(chatMatch[1]);
    const session = property ? getTravelerSession(req, property) : null;
    if (!property || !session) return sendJson(res, 403, { error: "Accès refusé" });
    const body = await readJsonBody(req);
    const message = String(body.message || "").trim().slice(0, Number(property.ai_max_input_chars || 700));
    if (!message) return sendJson(res, 400, { error: "Message vide" });
    const sessionCount = (await get("SELECT COUNT(*) AS count FROM chat_messages WHERE property_id = ? AND session_id = ? AND role = 'user'", [property.id, session.sessionId || ""])).count;
    const dailyCount = (await get("SELECT COUNT(*) AS count FROM chat_messages WHERE property_id = ? AND role = 'user' AND created_at >= ?", [property.id, new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()])).count;
    if (sessionCount >= Number(property.ai_session_limit || 20)) {
      return sendJson(res, 429, { error: "La limite de questions de cette session est atteinte. Utilisez le Centre de Services Liberty pour une demande précise." });
    }
    if (dailyCount >= Number(property.ai_daily_limit || 80)) {
      return sendJson(res, 429, { error: "L'assistant est temporairement limité pour maîtriser les coûts. Le Centre de Services Liberty reste disponible." });
    }
    await run("INSERT INTO chat_messages (property_id, role, content, session_id, created_at) VALUES (?, ?, ?, ?, ?)", [property.id, "user", message, session.sessionId || "", now()]);
    await recordAnalytics(property.id, "ai_question", "", session.sessionId || "");
    try {
      const answer = await callOpenAI(property, message);
      await run("INSERT INTO chat_messages (property_id, role, content, session_id, created_at) VALUES (?, ?, ?, ?, ?)", [property.id, "assistant", answer, session.sessionId || "", now()]);
      return sendJson(res, 200, { answer });
    } catch (error) {
      const fallback = `${localAssistantReply(property, message)} L'assistant IA est indisponible pour le moment ; si l'information n'est pas dans le livret, créez une demande dans le Centre de Services Liberty.`;
      return sendJson(res, 200, { answer: fallback, warning: error.message });
    }
  }

  return send(res, 404, "Page introuvable");
}

async function start() {
  db = await createDatabase();
  await initDb();

  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch((error) => {
      console.error(error);
      send(res, 500, "Erreur serveur Liberty");
    });
  });

  const host = process.env.HOST || "127.0.0.1";
  server.listen(PORT, host, () => {
    console.log(`Espace voyageurs Liberty prêt: ${BASE_URL} (${db.dialect})`);
  });
}

start().catch((error) => {
  console.error("Impossible de démarrer Conciergerie Liberty", error);
  process.exit(1);
});
