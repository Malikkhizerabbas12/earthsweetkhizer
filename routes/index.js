// routes/index.js - All EarthSweet API Routes
const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const db       = require('../database/db');
const { authCustomer, authAdmin } = require('../middleware/auth');

const router = express.Router();

// Helper: generate order number
const genOrderNum = () => {
  const d = new Date();
  const date = `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}`;
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `ES-${date}-${rand}`;
};

// Helper: send response
const ok  = (res, data, msg='Success') => res.json({ success:true, message:msg, ...data });
const err = (res, msg='Error', code=400) => res.status(code).json({ success:false, message:msg });

// ============================================================
// API INDEX & HEALTH CHECK
// ============================================================
router.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🌿 EarthSweet API',
    version: '1.0.0',
    time: new Date(),
    endpoints: {
      health:    'GET  /api/health',
      products:  'GET  /api/products',
      categories:'GET  /api/categories',
      cities:    'GET  /api/cities',
      register:  'POST /api/auth/register',
      login:     'POST /api/auth/login',
      me:        'GET  /api/auth/me',
      order:     'POST /api/orders',
      track:     'GET  /api/orders/:orderNumber',
      contact:   'POST /api/contact',
      adminLogin:'POST /api/admin/login',
      adminStats:'GET  /api/admin/stats',
    }
  });
});

router.get('/health', (req, res) => {
  res.json({ success: true, message: '🌿 EarthSweet API is running', time: new Date() });
});

// ============================================================
// PRODUCTS
// ============================================================

// GET /api/products - Get all active products
router.get('/products', async (req, res) => {
  try {
    const { category, featured } = req.query;
    let sql = `
      SELECT p.*, c.name_en as category_en, c.name_ur as category_ur, c.slug as category_slug
      FROM products p
      LEFT JOIN categories c ON p.category_id = c.id
      WHERE p.is_active = TRUE
    `;
    const params = [];
    if (category) { sql += ' AND c.slug = ?'; params.push(category); }
    if (featured)  { sql += ' AND p.is_featured = TRUE'; }
    sql += ' ORDER BY p.is_featured DESC, p.total_sold DESC';

    const [rows] = await db.execute(sql, params);
    ok(res, { products: rows, total: rows.length });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// GET /api/products/:slug - Single product
router.get('/products/:slug', async (req, res) => {
  try {
    const [rows] = await db.execute(
      `SELECT p.*, c.name_en as category_en, c.name_ur as category_ur
       FROM products p LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.slug = ? AND p.is_active = TRUE`, [req.params.slug]);
    if (!rows.length) return err(res, 'Product not found', 404);
    ok(res, { product: rows[0] });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// GET /api/categories - Get all categories
router.get('/categories', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM categories WHERE is_active=TRUE ORDER BY sort_order');
    ok(res, { categories: rows });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// GET /api/cities - Delivery cities
router.get('/cities', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM delivery_cities WHERE is_active=TRUE ORDER BY sort_order');
    ok(res, { cities: rows });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// ============================================================
// CUSTOMER AUTH
// ============================================================

// POST /api/auth/register
router.post('/auth/register', [
  body('full_name').trim().isLength({ min:2, max:100 }),
  body('phone').trim().isMobilePhone(),
  body('password').isLength({ min:6 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return err(res, errors.array()[0].msg);
  try {
    const { full_name, phone, email, city, password } = req.body;
    const [exists] = await db.execute('SELECT id FROM customers WHERE phone=?', [phone]);
    if (exists.length) return err(res, 'Phone number already registered');

    const hashed = await bcrypt.hash(password, 10);
    const [result] = await db.execute(
      'INSERT INTO customers (full_name, phone, email, city, password, is_active) VALUES (?,?,?,?,?,1)',
      [full_name, phone, email||null, city||null, hashed]
    );
    const token = jwt.sign({ id: result.insertId, role: 'customer' }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
    ok(res, { token, customer: { id: result.insertId, full_name, phone, city } }, 'Account created successfully');
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// POST /api/auth/login
router.post('/auth/login', [
  body('phone').trim().notEmpty(),
  body('password').notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return err(res, 'Phone and password required');
  try {
    const { phone, password } = req.body;
    const [rows] = await db.execute(
      'SELECT id, full_name, phone, city, password, is_active FROM customers WHERE phone=?', [phone]);
    if (!rows.length) return err(res, 'Invalid phone or password', 401);
    if (rows[0].is_active === 0) return err(res, 'Account is deactivated', 401);

    const match = await bcrypt.compare(password, rows[0].password);
    if (!match) return err(res, 'Invalid phone or password', 401);

    const token = jwt.sign({ id: rows[0].id, role: 'customer' }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
    const { password: _, ...customer } = rows[0];
    ok(res, { token, customer }, 'Login successful');
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// POST /api/auth/google — Firebase Google/Facebook login
router.post('/auth/google', async (req, res) => {
  try {
    const { email, full_name } = req.body;
    if (!email) return err(res, 'Email required', 400);

    // Check if customer already exists
    const [exists] = await db.execute('SELECT id, full_name, phone, city, is_active FROM customers WHERE email=?', [email]);

    let customer;
    if (exists.length) {
      // Existing user — update name if needed
      customer = exists[0];
      if (!customer.full_name && full_name) {
        await db.execute('UPDATE customers SET full_name=? WHERE id=?', [full_name, customer.id]);
        customer.full_name = full_name;
      }
    } else {
      // New user — create account
      const [result] = await db.execute(
        'INSERT INTO customers (full_name, email, phone, password, is_active) VALUES (?,?,?,?,1)',
        [full_name || email.split('@')[0], email, null, 'firebase_auth']
      );
      customer = { id: result.insertId, full_name: full_name || email.split('@')[0], email, phone: null, city: null };
    }

    const token = jwt.sign({ id: customer.id, role: 'customer' }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
    ok(res, { token, customer }, 'Google login successful');
  } catch (e) { console.error('GOOGLE AUTH ERROR:', e); err(res, e.message, 500); }
});

// GET /api/auth/me - Get logged in customer info
router.get('/auth/me', authCustomer, async (req, res) => {
  try {
    const [orders] = await db.execute(
      'SELECT id, order_number, total_amount, status, created_at FROM orders WHERE customer_id=? ORDER BY created_at DESC LIMIT 10',
      [req.customer.id]);
    ok(res, { customer: req.customer, orders });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// ============================================================
// ORDERS
// ============================================================

// POST /api/orders - Place an order (public or logged in)
router.post('/orders', [
  body('customer_name').trim().isLength({ min:2 }),
  body('customer_phone').trim().notEmpty(),
  body('customer_city').trim().notEmpty(),
  body('items').isArray({ min:1 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return err(res, errors.array()[0].msg);

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const { customer_name, customer_phone, customer_city, delivery_address, items, notes, payment_method } = req.body;
    
    // Validate customer_id - must exist in customers table
    let customer_id = null;
    if (req.body.customer_id) {
      const [custCheck] = await conn.execute('SELECT id FROM customers WHERE id=?', [req.body.customer_id]);
      customer_id = custCheck.length ? req.body.customer_id : null;
    }

    // Get delivery fee
    const [cityRow] = await conn.execute('SELECT delivery_fee FROM delivery_cities WHERE city_name=?', [customer_city]);
    const deliveryFee = cityRow.length ? parseFloat(cityRow[0].delivery_fee) : 200;

    // Calculate subtotal & validate products
    let subtotal = 0;
    const orderItems = [];
    for (const item of items) {
      const [prod] = await conn.execute('SELECT id, name_en, price, unit, stock_qty FROM products WHERE id=? AND is_active=TRUE', [item.product_id]);
      if (!prod.length) throw new Error(`Product ID ${item.product_id} not found`);
      if (prod[0].stock_qty < item.quantity) throw new Error(`Insufficient stock for ${prod[0].name_en}`);
      const total = parseFloat(prod[0].price) * parseInt(item.quantity);
      subtotal += total;
      orderItems.push({ ...prod[0], quantity: item.quantity, unit_price: prod[0].price, total_price: total });
    }

    // Check free delivery
    const [feeSetting] = await conn.execute("SELECT setting_val FROM site_settings WHERE setting_key='free_delivery_above'");
    const freeAbove = feeSetting.length ? parseFloat(feeSetting[0].setting_val) : 2000;
    const finalDelivery = subtotal >= freeAbove ? 0 : deliveryFee;
    const totalAmount = subtotal + finalDelivery;

    // Create order
    const orderNumber = genOrderNum();
    const [orderResult] = await conn.execute(
      `INSERT INTO orders (order_number, customer_id, customer_name, customer_phone, customer_city, delivery_address, subtotal, delivery_fee, total_amount, payment_method, notes)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [orderNumber, customer_id||null, customer_name, customer_phone, customer_city, delivery_address||null, subtotal, finalDelivery, totalAmount, payment_method||'cod', notes||null]
    );
    const orderId = orderResult.insertId;

    // Insert order items & update stock
    for (const item of orderItems) {
      await conn.execute(
        'INSERT INTO order_items (order_id, product_id, product_name, product_unit, quantity, unit_price, total_price) VALUES (?,?,?,?,?,?,?)',
        [orderId, item.id, item.name_en, item.unit, item.quantity, item.unit_price, item.total_price]
      );
      await conn.execute('UPDATE products SET stock_qty = stock_qty - ?, total_sold = total_sold + ? WHERE id=?',
        [item.quantity, item.quantity, item.id]);
    }

    // Update customer order count
    if (customer_id) await conn.execute('UPDATE customers SET total_orders = total_orders + 1 WHERE id=?', [customer_id]);

    await conn.commit();
    ok(res, { order_number: orderNumber, order_id: orderId, total_amount: totalAmount, delivery_fee: finalDelivery }, 'Order placed successfully');
  } catch (e) {
    await conn.rollback();
    err(res, e.message, 500);
  } finally { conn.release(); }
});

// GET /api/orders/:orderNumber - Track order (public)
router.get('/orders/:orderNumber', async (req, res) => {
  try {
    const [rows] = await db.execute(
      'SELECT id, order_number, customer_name, customer_city, total_amount, status, payment_status, created_at, confirmed_at, shipped_at, delivered_at FROM orders WHERE order_number=?',
      [req.params.orderNumber.toUpperCase()]
    );
    if (!rows.length) return err(res, 'Order not found', 404);
    const [items] = await db.execute('SELECT * FROM order_items WHERE order_id=?', [rows[0].id]);
    ok(res, { order: { ...rows[0], items } });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// ============================================================
// CONTACT
// ============================================================
router.post('/contact', [
  body('name').trim().isLength({ min:2 }),
  body('message').trim().isLength({ min:5 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return err(res, errors.array()[0].msg);
  try {
    const { name, phone, email, message } = req.body;
    await db.execute('INSERT INTO contact_messages (name, phone, email, message) VALUES (?,?,?,?)',
      [name, phone||null, email||null, message]);
    ok(res, {}, 'Message sent successfully');
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// ============================================================
// ADMIN AUTH
// ============================================================

// POST /api/admin/login
router.post('/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return err(res, 'Username and password required');

    const [rows] = await db.execute('SELECT * FROM admins WHERE username=? AND is_active=TRUE', [username]);
    if (!rows.length) return err(res, 'Invalid credentials', 401);

    const match = await bcrypt.compare(password, rows[0].password);
    if (!match) return err(res, 'Invalid credentials', 401);

    await db.execute('UPDATE admins SET last_login=NOW() WHERE id=?', [rows[0].id]);
    const token = jwt.sign({ id: rows[0].id, role: 'admin', username }, process.env.JWT_SECRET, { expiresIn: '1d' });
    ok(res, { token, admin: { id: rows[0].id, username, full_name: rows[0].full_name, role: rows[0].role } }, 'Admin login successful');
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// ============================================================
// ADMIN - DASHBOARD STATS
// ============================================================
router.get('/admin/stats', authAdmin, async (req, res) => {
  try {
    const [[orders]]    = await db.execute('SELECT COUNT(*) as total, SUM(total_amount) as revenue FROM orders');
    const [[pending]]   = await db.execute("SELECT COUNT(*) as cnt FROM orders WHERE status='pending'");
    const [[customers]] = await db.execute('SELECT COUNT(*) as total FROM customers');
    const [[messages]]  = await db.execute('SELECT COUNT(*) as unread FROM contact_messages WHERE is_read=FALSE');
    const [topProducts] = await db.execute('SELECT name_en, total_sold, price FROM products ORDER BY total_sold DESC LIMIT 5');
    const [recentOrders]= await db.execute('SELECT order_number, customer_name, customer_city, total_amount, status, created_at FROM orders ORDER BY created_at DESC LIMIT 10');
    ok(res, { stats: { total_orders: orders.total, total_revenue: orders.revenue||0, pending_orders: pending.cnt, total_customers: customers.total, unread_messages: messages.unread }, topProducts, recentOrders });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// ============================================================
// ADMIN - ORDER MANAGEMENT
// ============================================================

// GET /api/admin/orders
router.get('/admin/orders', authAdmin, async (req, res) => {
  try {
    const { status, page=1, limit=20 } = req.query;
    const offset = (page - 1) * limit;
    let sql = 'SELECT o.*, GROUP_CONCAT(oi.product_name, " x", oi.quantity SEPARATOR ", ") as items_summary FROM orders o LEFT JOIN order_items oi ON o.id=oi.order_id';
    const params = [];
    if (status) { sql += ' WHERE o.status=?'; params.push(status); }
    sql += ' GROUP BY o.id ORDER BY o.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const [rows] = await db.execute(sql, params);
    const [[count]] = await db.execute('SELECT COUNT(*) as total FROM orders' + (status ? ' WHERE status=?' : ''), status ? [status] : []);
    ok(res, { orders: rows, total: count.total, page: parseInt(page), pages: Math.ceil(count.total/limit) });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// PATCH /api/admin/orders/:id/status
router.patch('/admin/orders/:id/status', authAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const valid = ['pending','confirmed','processing','shipped','delivered','cancelled'];
    if (!valid.includes(status)) return err(res, 'Invalid status');

    const updates = { status };
    if (status === 'confirmed') updates.confirmed_at = new Date();
    if (status === 'shipped')   updates.shipped_at   = new Date();
    if (status === 'delivered') updates.delivered_at = new Date();

    const sets = Object.keys(updates).map(k => `${k}=?`).join(', ');
    await db.execute(`UPDATE orders SET ${sets} WHERE id=?`, [...Object.values(updates), req.params.id]);
    ok(res, {}, `Order status updated to ${status}`);
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// PATCH /api/admin/orders/:id/payment-status
router.patch('/admin/orders/:id/payment-status', authAdmin, async (req, res) => {
  try {
    const { payment_status } = req.body;
    const valid = ['unpaid', 'paid', 'refunded'];
    if (!valid.includes(payment_status)) return err(res, 'Invalid payment_status');
    await db.execute('UPDATE orders SET payment_status=? WHERE id=?', [payment_status, req.params.id]);
    ok(res, {}, `Payment status updated to ${payment_status}`);
  } catch (e) { err(res, e.message, 500); }
});

// ============================================================
// ADMIN - PRODUCT MANAGEMENT
// ============================================================

// GET /api/admin/products
router.get('/admin/products', authAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT p.*, c.name_en as category FROM products p LEFT JOIN categories c ON p.category_id=c.id ORDER BY p.created_at DESC');
    ok(res, { products: rows });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// POST /api/admin/products
router.post('/admin/products', authAdmin, async (req, res) => {
  try {
    const { category_id, name_en, name_ur, slug, description_en, description_ur, price, price_wholesale, unit, stock_qty, badge, emoji, is_featured } = req.body;
    if (!name_en || !price) return err(res, 'Name and price required');
    const [result] = await db.execute(
      'INSERT INTO products (category_id, name_en, name_ur, slug, description_en, description_ur, price, price_wholesale, unit, stock_qty, badge, emoji, is_featured) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [category_id, name_en, name_ur||null, slug||name_en.toLowerCase().replace(/\s+/g,'-'), description_en||null, description_ur||null, price, price_wholesale||null, unit||'kg', stock_qty||0, badge||null, emoji||'🌾', is_featured||false]
    );
    ok(res, { product_id: result.insertId }, 'Product created');
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// PUT /api/admin/products/:id
router.put('/admin/products/:id', authAdmin, async (req, res) => {
  try {
    const { name_en, name_ur, price, price_wholesale, stock_qty, badge, is_active, is_featured, description_en, description_ur } = req.body;
    await db.execute(
      'UPDATE products SET name_en=?, name_ur=?, price=?, price_wholesale=?, stock_qty=?, badge=?, is_active=?, is_featured=?, description_en=?, description_ur=? WHERE id=?',
      [name_en, name_ur||null, price, price_wholesale||null, stock_qty||0, badge||null, is_active!==false, is_featured||false, description_en||null, description_ur||null, req.params.id]
    );
    ok(res, {}, 'Product updated');
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// DELETE /api/admin/products/:id (soft delete)
router.delete('/admin/products/:id', authAdmin, async (req, res) => {
  try {
    await db.execute('UPDATE products SET is_active=FALSE WHERE id=?', [req.params.id]);
    ok(res, {}, 'Product deactivated');
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// ============================================================
// ADMIN - CUSTOMERS
// ============================================================
router.get('/admin/customers', authAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT id, full_name, phone, email, city, total_orders, is_active, created_at FROM customers ORDER BY created_at DESC');
    ok(res, { customers: rows, total: rows.length });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// ============================================================
// ADMIN - MESSAGES
// ============================================================
router.get('/admin/messages', authAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM contact_messages ORDER BY created_at DESC');
    ok(res, { messages: rows });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

router.patch('/admin/messages/:id/read', authAdmin, async (req, res) => {
  try {
    await db.execute('UPDATE contact_messages SET is_read=TRUE WHERE id=?', [req.params.id]);
    ok(res, {}, 'Marked as read');
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

// ============================================================
// ADMIN - SETTINGS
// ============================================================
router.get('/admin/settings', authAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT setting_key, setting_val FROM site_settings');
    const settings = {};
    rows.forEach(r => settings[r.setting_key] = r.setting_val);
    ok(res, { settings });
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

router.put('/admin/settings', authAdmin, async (req, res) => {
  try {
    const { settings } = req.body;
    for (const [key, val] of Object.entries(settings)) {
      await db.execute('INSERT INTO site_settings (setting_key, setting_val) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_val=?', [key, val, val]);
    }
    ok(res, {}, 'Settings updated');
  } catch (e) { console.error('LOGIN ERROR:', e); err(res, e.message, 500); }
});

module.exports = router;