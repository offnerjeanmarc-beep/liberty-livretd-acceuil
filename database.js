const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const mysql = require("mysql2/promise");

const DATA_DIR = path.join(__dirname, "data");
const SQLITE_PATH = path.join(DATA_DIR, "liberty.sqlite");

function normalizeSql(sql, dialect) {
  if (dialect !== "mysql") return sql;
  return sql.replace(/\?/g, "?");
}

function toMysqlUrl(databaseUrl) {
  const url = new URL(databaseUrl);
  if (url.protocol === "mysql:") return databaseUrl;
  if (url.protocol === "mysql2:") {
    url.protocol = "mysql:";
    return url.toString();
  }
  return databaseUrl;
}

async function createDatabase() {
  const databaseUrl = process.env.DATABASE_URL || `sqlite:${SQLITE_PATH}`;

  if (databaseUrl.startsWith("mysql://") || databaseUrl.startsWith("mysql2://")) {
    const pool = mysql.createPool({
      uri: toMysqlUrl(databaseUrl),
      waitForConnections: true,
      connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
      namedPlaceholders: false,
      charset: "utf8mb4",
    });

    return {
      dialect: "mysql",
      async run(sql, params = []) {
        const [result] = await pool.execute(normalizeSql(sql, "mysql"), params);
        return result;
      },
      async get(sql, params = []) {
        const [rows] = await pool.execute(normalizeSql(sql, "mysql"), params);
        return rows[0];
      },
      async all(sql, params = []) {
        const [rows] = await pool.execute(normalizeSql(sql, "mysql"), params);
        return rows;
      },
      async close() {
        await pool.end();
      },
    };
  }

  fs.mkdirSync(DATA_DIR, { recursive: true });
  const sqlitePath = databaseUrl.startsWith("sqlite:")
    ? databaseUrl.slice("sqlite:".length)
    : SQLITE_PATH;
  const db = new DatabaseSync(sqlitePath);

  return {
    dialect: "sqlite",
    async run(sql, params = []) {
      return db.prepare(sql).run(...params);
    },
    async get(sql, params = []) {
      return db.prepare(sql).get(...params);
    },
    async all(sql, params = []) {
      return db.prepare(sql).all(...params);
    },
    async close() {
      db.close();
    },
  };
}

module.exports = { createDatabase };
