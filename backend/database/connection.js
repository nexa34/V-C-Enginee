const mysql = require('mysql2/promise');
const config = require('../config/env');

const pool = mysql.createPool({
  host: config.DB.host,
  port: config.DB.port,
  user: config.DB.user,
  password: config.DB.password,
  database: config.DB.database,
  waitForConnections: true,
  connectionLimit: 20,
  queueLimit: 0,
  charset: 'utf8mb4',
});

pool.getConnection()
  .then(conn => { console.log('[DB] Connected to MySQL'); conn.release(); })
  .catch(err => { console.error('[DB] Connection failed:', err.message); process.exit(1); });

module.exports = pool;