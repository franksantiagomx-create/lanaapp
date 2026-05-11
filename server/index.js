require('dotenv').config();
const express  = require('express');
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const path     = require('path');
const cors     = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'lana-secret-cambiar-en-produccion';

// ── Base de datos ─────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
    -- Usuarios
    CREATE TABLE IF NOT EXISTS usuarios (
      id           SERIAL PRIMARY KEY,
      nombre       TEXT NOT NULL,
      correo       TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      tipo_ingreso TEXT DEFAULT 'quincenal',
      monto_base   NUMERIC(14,2) DEFAULT 0,
      dia_cobro    INTEGER DEFAULT 1,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );

    -- Cuentas (efectivo, débito, crédito, ahorro)
    CREATE TABLE IF NOT EXISTS cuentas (
      id          SERIAL PRIMARY KEY,
      usuario_id  INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
      nombre      TEXT NOT NULL,
      tipo        TEXT DEFAULT 'debito',
      saldo       NUMERIC(14,2) DEFAULT 0,
      color       TEXT DEFAULT '#1A1916',
      icono       TEXT DEFAULT 'wallet',
      limite_credito NUMERIC(14,2) DEFAULT 0,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    -- Categorías de gastos
    CREATE TABLE IF NOT EXISTS categorias_gasto (
      id         SERIAL PRIMARY KEY,
      usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
      nombre     TEXT NOT NULL,
      icono      TEXT DEFAULT 'tag',
      color      TEXT DEFAULT '#1A1916',
      es_default BOOLEAN DEFAULT false
    );

    -- Categorías de ingresos
    CREATE TABLE IF NOT EXISTS categorias_ingreso (
      id         SERIAL PRIMARY KEY,
      usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
      nombre     TEXT NOT NULL,
      icono      TEXT DEFAULT 'cash',
      es_default BOOLEAN DEFAULT false
    );

    -- Periodos (cada quincena/semana/mes)
    CREATE TABLE IF NOT EXISTS periodos (
      id          SERIAL PRIMARY KEY,
      usuario_id  INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
      tipo        TEXT NOT NULL,
      fecha_inicio DATE NOT NULL,
      fecha_fin    DATE NOT NULL,
      monto_base   NUMERIC(14,2) NOT NULL,
      activo       BOOLEAN DEFAULT true,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );

    -- Movimientos (gastos e ingresos)
    CREATE TABLE IF NOT EXISTS movimientos (
      id             SERIAL PRIMARY KEY,
      usuario_id     INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
      periodo_id     INTEGER REFERENCES periodos(id) ON DELETE SET NULL,
      cuenta_id      INTEGER REFERENCES cuentas(id) ON DELETE SET NULL,
      categoria_id   INTEGER,
      tipo           TEXT NOT NULL CHECK (tipo IN ('gasto','ingreso')),
      subtipo        TEXT DEFAULT 'normal',
      monto          NUMERIC(14,2) NOT NULL,
      descripcion    TEXT,
      fecha          DATE NOT NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    );

    -- Configuración general por usuario
    CREATE TABLE IF NOT EXISTS config_usuario (
      id         SERIAL PRIMARY KEY,
      usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
      clave      TEXT NOT NULL,
      valor      TEXT,
      UNIQUE(usuario_id, clave)
    );
  `);
  console.log('✅ Base de datos lista');
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Middleware de autenticación
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'No autorizado' });
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ── AUTH: Registro ────────────────────────────────────────────────────────────
app.post('/api/auth/registro', async (req, res) => {
  const { nombre, correo, password, tipo_ingreso, monto_base } = req.body;
  if (!nombre || !correo || !password)
    return res.status(400).json({ error: 'Nombre, correo y contraseña son requeridos' });
  if (password.length < 6)
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

  try {
    const existe = await pool.query('SELECT id FROM usuarios WHERE correo=$1', [correo.toLowerCase()]);
    if (existe.rows.length)
      return res.status(409).json({ error: 'Ya existe una cuenta con ese correo' });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO usuarios (nombre, correo, password_hash, tipo_ingreso, monto_base)
       VALUES ($1,$2,$3,$4,$5) RETURNING id, nombre, correo, tipo_ingreso, monto_base`,
      [nombre.trim(), correo.toLowerCase().trim(), hash, tipo_ingreso || 'quincenal', monto_base || 0]
    );
    const usuario = result.rows[0];

    // Crear cuentas y categorías predeterminadas
    await crearDefaults(usuario.id, nombre.trim());

    // Crear periodo activo inicial
    await crearPeriodoActivo(usuario.id, tipo_ingreso || 'quincenal', monto_base || 0);

    const token = jwt.sign({ userId: usuario.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, usuario });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── AUTH: Login ───────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { correo, password } = req.body;
  if (!correo || !password)
    return res.status(400).json({ error: 'Correo y contraseña requeridos' });

  try {
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE correo=$1', [correo.toLowerCase().trim()]
    );
    if (!result.rows.length)
      return res.status(401).json({ error: 'Correo o contraseña incorrectos' });

    const usuario = result.rows[0];
    const ok = await bcrypt.compare(password, usuario.password_hash);
    if (!ok)
      return res.status(401).json({ error: 'Correo o contraseña incorrectos' });

    const token = jwt.sign({ userId: usuario.id }, JWT_SECRET, { expiresIn: '30d' });
    delete usuario.password_hash;
    res.json({ token, usuario });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── AUTH: Perfil actual ───────────────────────────────────────────────────────
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre, correo, tipo_ingreso, monto_base, dia_cobro, created_at FROM usuarios WHERE id=$1',
      [req.userId]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── AUTH: Actualizar perfil ───────────────────────────────────────────────────
app.put('/api/auth/perfil', auth, async (req, res) => {
  const { nombre, tipo_ingreso, monto_base, dia_cobro } = req.body;
  try {
    const result = await pool.query(
      `UPDATE usuarios SET nombre=COALESCE($1,nombre), tipo_ingreso=COALESCE($2,tipo_ingreso),
       monto_base=COALESCE($3,monto_base), dia_cobro=COALESCE($4,dia_cobro)
       WHERE id=$5 RETURNING id, nombre, correo, tipo_ingreso, monto_base, dia_cobro`,
      [nombre, tipo_ingreso, monto_base, dia_cobro, req.userId]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── CUENTAS ───────────────────────────────────────────────────────────────────
app.get('/api/cuentas', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM cuentas WHERE usuario_id=$1 ORDER BY created_at',
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/cuentas', auth, async (req, res) => {
  const { nombre, tipo, saldo, color, icono, limite_credito } = req.body;
  if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });
  try {
    const result = await pool.query(
      `INSERT INTO cuentas (usuario_id, nombre, tipo, saldo, color, icono, limite_credito)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [req.userId, nombre, tipo||'debito', saldo||0, color||'#1A1916', icono||'wallet', limite_credito||0]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/cuentas/:id', auth, async (req, res) => {
  const { nombre, tipo, saldo, color, icono, limite_credito } = req.body;
  try {
    const result = await pool.query(
      `UPDATE cuentas SET nombre=COALESCE($1,nombre), tipo=COALESCE($2,tipo),
       saldo=COALESCE($3,saldo), color=COALESCE($4,color), icono=COALESCE($5,icono),
       limite_credito=COALESCE($6,limite_credito)
       WHERE id=$7 AND usuario_id=$8 RETURNING *`,
      [nombre, tipo, saldo, color, icono, limite_credito, req.params.id, req.userId]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/cuentas/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM cuentas WHERE id=$1 AND usuario_id=$2', [req.params.id, req.userId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── CATEGORÍAS GASTO ──────────────────────────────────────────────────────────
app.get('/api/categorias/gasto', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM categorias_gasto WHERE usuario_id=$1 ORDER BY es_default DESC, nombre',
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/categorias/gasto', auth, async (req, res) => {
  const { nombre, icono, color } = req.body;
  if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });
  try {
    const result = await pool.query(
      'INSERT INTO categorias_gasto (usuario_id, nombre, icono, color) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.userId, nombre, icono||'tag', color||'#1A1916']
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/categorias/gasto/:id', auth, async (req, res) => {
  const { nombre, icono, color } = req.body;
  try {
    const result = await pool.query(
      `UPDATE categorias_gasto SET nombre=COALESCE($1,nombre), icono=COALESCE($2,icono), color=COALESCE($3,color)
       WHERE id=$4 AND usuario_id=$5 RETURNING *`,
      [nombre, icono, color, req.params.id, req.userId]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/categorias/gasto/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM categorias_gasto WHERE id=$1 AND usuario_id=$2 AND es_default=false', [req.params.id, req.userId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── CATEGORÍAS INGRESO ────────────────────────────────────────────────────────
app.get('/api/categorias/ingreso', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM categorias_ingreso WHERE usuario_id=$1 ORDER BY es_default DESC, nombre',
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/categorias/ingreso', auth, async (req, res) => {
  const { nombre, icono } = req.body;
  if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });
  try {
    const result = await pool.query(
      'INSERT INTO categorias_ingreso (usuario_id, nombre, icono) VALUES ($1,$2,$3) RETURNING *',
      [req.userId, nombre, icono||'cash']
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/categorias/ingreso/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM categorias_ingreso WHERE id=$1 AND usuario_id=$2 AND es_default=false', [req.params.id, req.userId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── PERIODOS ──────────────────────────────────────────────────────────────────
app.get('/api/periodos', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*,
        COALESCE(SUM(m.monto) FILTER (WHERE m.tipo='ingreso'), 0) AS total_ingresos,
        COALESCE(SUM(m.monto) FILTER (WHERE m.tipo='gasto'), 0) AS total_gastos
       FROM periodos p
       LEFT JOIN movimientos m ON m.periodo_id = p.id
       WHERE p.usuario_id=$1
       GROUP BY p.id
       ORDER BY p.fecha_inicio DESC LIMIT 10`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/periodos/activo', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*,
        COALESCE(SUM(m.monto) FILTER (WHERE m.tipo='ingreso'), 0) AS total_ingresos,
        COALESCE(SUM(m.monto) FILTER (WHERE m.tipo='gasto'), 0) AS total_gastos,
        COALESCE(SUM(m.monto) FILTER (WHERE m.tipo='ingreso' AND m.subtipo='extra'), 0) AS total_extras
       FROM periodos p
       LEFT JOIN movimientos m ON m.periodo_id = p.id
       WHERE p.usuario_id=$1 AND p.activo=true
       GROUP BY p.id
       ORDER BY p.fecha_inicio DESC LIMIT 1`,
      [req.userId]
    );
    res.json(result.rows[0] || null);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/periodos', auth, async (req, res) => {
  const { tipo, fecha_inicio, fecha_fin, monto_base } = req.body;
  try {
    // Desactivar periodo anterior
    await pool.query('UPDATE periodos SET activo=false WHERE usuario_id=$1 AND activo=true', [req.userId]);
    const result = await pool.query(
      `INSERT INTO periodos (usuario_id, tipo, fecha_inicio, fecha_fin, monto_base)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.userId, tipo, fecha_inicio, fecha_fin, monto_base]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── MOVIMIENTOS ───────────────────────────────────────────────────────────────
app.get('/api/movimientos', auth, async (req, res) => {
  const { periodo_id, tipo, limit = 50 } = req.query;
  try {
    let query = `
      SELECT m.*, c.nombre AS cuenta_nombre,
        CASE WHEN m.tipo='gasto' THEN cg.nombre ELSE ci.nombre END AS categoria_nombre
      FROM movimientos m
      LEFT JOIN cuentas c ON c.id = m.cuenta_id
      LEFT JOIN categorias_gasto cg ON cg.id = m.categoria_id AND m.tipo='gasto'
      LEFT JOIN categorias_ingreso ci ON ci.id = m.categoria_id AND m.tipo='ingreso'
      WHERE m.usuario_id = $1
    `;
    const params = [req.userId];
    if (periodo_id) { params.push(periodo_id); query += ` AND m.periodo_id = $${params.length}`; }
    if (tipo) { params.push(tipo); query += ` AND m.tipo = $${params.length}`; }
    params.push(limit);
    query += ` ORDER BY m.fecha DESC, m.created_at DESC LIMIT $${params.length}`;
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/movimientos', auth, async (req, res) => {
  const { periodo_id, cuenta_id, categoria_id, tipo, subtipo, monto, descripcion, fecha } = req.body;
  if (!tipo || !monto || !fecha)
    return res.status(400).json({ error: 'tipo, monto y fecha son requeridos' });
  try {
    const result = await pool.query(
      `INSERT INTO movimientos (usuario_id, periodo_id, cuenta_id, categoria_id, tipo, subtipo, monto, descripcion, fecha)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.userId, periodo_id, cuenta_id, categoria_id, tipo, subtipo||'normal', monto, descripcion, fecha]
    );
    // Actualizar saldo de la cuenta
    if (cuenta_id) {
      const delta = tipo === 'ingreso' ? monto : -monto;
      await pool.query('UPDATE cuentas SET saldo = saldo + $1 WHERE id=$2 AND usuario_id=$3', [delta, cuenta_id, req.userId]);
    }
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/movimientos/:id', auth, async (req, res) => {
  const { categoria_id, monto, descripcion, fecha, cuenta_id } = req.body;
  try {
    // Revertir efecto anterior en cuenta
    const old = await pool.query('SELECT * FROM movimientos WHERE id=$1 AND usuario_id=$2', [req.params.id, req.userId]);
    if (!old.rows.length) return res.status(404).json({ error: 'No encontrado' });
    const oldMov = old.rows[0];
    if (oldMov.cuenta_id) {
      const revert = oldMov.tipo === 'ingreso' ? -oldMov.monto : oldMov.monto;
      await pool.query('UPDATE cuentas SET saldo = saldo + $1 WHERE id=$2 AND usuario_id=$3', [revert, oldMov.cuenta_id, req.userId]);
    }
    const result = await pool.query(
      `UPDATE movimientos SET categoria_id=COALESCE($1,categoria_id), monto=COALESCE($2,monto),
       descripcion=COALESCE($3,descripcion), fecha=COALESCE($4,fecha), cuenta_id=COALESCE($5,cuenta_id)
       WHERE id=$6 AND usuario_id=$7 RETURNING *`,
      [categoria_id, monto, descripcion, fecha, cuenta_id, req.params.id, req.userId]
    );
    // Aplicar nuevo efecto en cuenta
    const updated = result.rows[0];
    if (updated.cuenta_id) {
      const delta = updated.tipo === 'ingreso' ? updated.monto : -updated.monto;
      await pool.query('UPDATE cuentas SET saldo = saldo + $1 WHERE id=$2 AND usuario_id=$3', [delta, updated.cuenta_id, req.userId]);
    }
    res.json(updated);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/movimientos/:id', auth, async (req, res) => {
  try {
    const old = await pool.query('SELECT * FROM movimientos WHERE id=$1 AND usuario_id=$2', [req.params.id, req.userId]);
    if (old.rows.length && old.rows[0].cuenta_id) {
      const mov = old.rows[0];
      const revert = mov.tipo === 'ingreso' ? -mov.monto : mov.monto;
      await pool.query('UPDATE cuentas SET saldo = saldo + $1 WHERE id=$2 AND usuario_id=$3', [revert, mov.cuenta_id, req.userId]);
    }
    await pool.query('DELETE FROM movimientos WHERE id=$1 AND usuario_id=$2', [req.params.id, req.userId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── RESUMEN DASHBOARD ─────────────────────────────────────────────────────────
app.get('/api/resumen', auth, async (req, res) => {
  try {
    const periodo = await pool.query(
      `SELECT p.*,
        COALESCE(SUM(m.monto) FILTER (WHERE m.tipo='ingreso'), 0) AS total_ingresos,
        COALESCE(SUM(m.monto) FILTER (WHERE m.tipo='gasto'), 0) AS total_gastos,
        COALESCE(SUM(m.monto) FILTER (WHERE m.tipo='ingreso' AND m.subtipo='extra'), 0) AS extras
       FROM periodos p LEFT JOIN movimientos m ON m.periodo_id=p.id
       WHERE p.usuario_id=$1 AND p.activo=true GROUP BY p.id`,
      [req.userId]
    );
    const cuentas = await pool.query(
      'SELECT COALESCE(SUM(saldo),0) AS total FROM cuentas WHERE usuario_id=$1', [req.userId]
    );
    const ultimos = await pool.query(
      `SELECT m.*, c.nombre AS cuenta_nombre,
        CASE WHEN m.tipo='gasto' THEN cg.nombre ELSE ci.nombre END AS categoria_nombre
       FROM movimientos m
       LEFT JOIN cuentas c ON c.id=m.cuenta_id
       LEFT JOIN categorias_gasto cg ON cg.id=m.categoria_id AND m.tipo='gasto'
       LEFT JOIN categorias_ingreso ci ON ci.id=m.categoria_id AND m.tipo='ingreso'
       WHERE m.usuario_id=$1 ORDER BY m.fecha DESC, m.created_at DESC LIMIT 5`,
      [req.userId]
    );
    res.json({
      periodo: periodo.rows[0] || null,
      total_cuentas: parseFloat(cuentas.rows[0].total),
      ultimos_movimientos: ultimos.rows,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── HELPERS ───────────────────────────────────────────────────────────────────
async function crearDefaults(userId, nombre) {
  // Cuentas por default
  await pool.query(
    `INSERT INTO cuentas (usuario_id, nombre, tipo, saldo, icono, color) VALUES
     ($1,'Efectivo','efectivo',0,'wallet','#1A1916'),
     ($1,'Mi cuenta débito','debito',0,'credit-card','#185FA5')`,
    [userId]
  );
  // Categorías de gasto por default
  const catGasto = ['Despensa','Gasolina','Comida fuera','Transporte','Renta','Servicios','Salud','Entretenimiento','Ropa','Otros'];
  for (const cat of catGasto) {
    await pool.query(
      'INSERT INTO categorias_gasto (usuario_id, nombre, es_default) VALUES ($1,$2,true)',
      [userId, cat]
    );
  }
  // Categorías de ingreso por default
  const catIngreso = ['Sueldo','Trabajo extra','Venta','Honorarios','Regalo','Otros ingresos'];
  for (const cat of catIngreso) {
    await pool.query(
      'INSERT INTO categorias_ingreso (usuario_id, nombre, es_default) VALUES ($1,$2,true)',
      [userId, cat]
    );
  }
}

async function crearPeriodoActivo(userId, tipo, monto) {
  const hoy = new Date();
  let inicio, fin;
  if (tipo === 'quincenal') {
    const dia = hoy.getDate();
    if (dia <= 15) {
      inicio = new Date(hoy.getFullYear(), hoy.getMonth(), 1);
      fin    = new Date(hoy.getFullYear(), hoy.getMonth(), 15);
    } else {
      inicio = new Date(hoy.getFullYear(), hoy.getMonth(), 16);
      fin    = new Date(hoy.getFullYear(), hoy.getMonth()+1, 0);
    }
  } else if (tipo === 'semanal') {
    const day = hoy.getDay();
    inicio = new Date(hoy); inicio.setDate(hoy.getDate() - day);
    fin    = new Date(inicio); fin.setDate(inicio.getDate() + 6);
  } else {
    inicio = new Date(hoy.getFullYear(), hoy.getMonth(), 1);
    fin    = new Date(hoy.getFullYear(), hoy.getMonth()+1, 0);
  }
  const fmt = d => d.toISOString().split('T')[0];
  await pool.query(
    'INSERT INTO periodos (usuario_id, tipo, fecha_inicio, fecha_fin, monto_base) VALUES ($1,$2,$3,$4,$5)',
    [userId, tipo, fmt(inicio), fmt(fin), monto]
  );
}

// ── Catch-all SPA ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ── Arrancar ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`🚀 lana. corriendo en puerto ${PORT}`));

async function initDBWithRetry(intentos = 10, espera = 3000) {
  for (let i = 1; i <= intentos; i++) {
    try { await initDB(); console.log('✅ DB conectada'); return; }
    catch (err) {
      console.error(`❌ Intento ${i}/${intentos}:`, err.message);
      if (i < intentos) await new Promise(r => setTimeout(r, espera));
    }
  }
}
initDBWithRetry();
