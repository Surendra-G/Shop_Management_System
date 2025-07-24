require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const pool = require('./database/database'); 
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

// Helper function to hash sensitive data
function hashData(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Middleware
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(bodyParser.json());

// JWT Authentication Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    console.log('No token provided');
    return res.sendStatus(401);
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    console.log('Decoded token:', decoded);
    
    const [shops] = await pool.query('SELECT * FROM shops WHERE id = ?', [decoded.shopId]);
    
    if (shops.length === 0) {
      console.log('Shop not found in database');
      return res.sendStatus(403);
    }
    
    req.user = shops[0];
    next();
  } catch (err) {
    console.error('JWT verification error:', err);
    
    if (err.name === 'TokenExpiredError') {
      return res.status(403).json({ error: 'Token expired' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    return res.sendStatus(403);
  }
};

// Shop Registration Route
app.post('/api/shop/signup', async (req, res) => {
  try {
    const { shopName, ownerName, email, phone, address, password, confirmPassword, businessType } = req.body;

    if (!shopName || !ownerName || !email || !password || !confirmPassword || !businessType) {
      console.log('Missing required fields');
      return res.status(400).json({ error: 'All required fields must be provided' });
    }

    if (password !== confirmPassword) {
      console.log('Passwords do not match');
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    if (password.length < 8) {
      console.log('Password must be at least 8 characters');
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const [existingShops] = await pool.query('SELECT * FROM shops WHERE email = ?', [email]);
    if (existingShops.length > 0) {
      console.log('Email already in use');
      return res.status(400).json({ error: 'Email already in use' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const [result] = await pool.query(
      'INSERT INTO shops (shop_name, owner_name, email, phone, address, password, business_type) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [shopName, ownerName, email, phone, address, hashedPassword, businessType]
    );

    const token = jwt.sign(
      { shopId: result.insertId, email: email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'Shop registered successfully',
      shop: {
        id: result.insertId,
        shopName,
        ownerName,
        email,
        businessType
      },
      token
    });
  } catch (error) {
    console.error('Shop registration error:', { message: error.message, stack: error.stack });
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Shop Login Route
app.post('/api/shop/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const [shops] = await pool.query('SELECT * FROM shops WHERE email = ?', [email]);
    if (shops.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const shop = shops[0];
    const passwordMatch = await bcrypt.compare(password, shop.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { shopId: shop.id, email: shop.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    const shopData = {
      id: shop.id,
      shopName: shop.shop_name,
      ownerName: shop.owner_name,
      email: shop.email,
      businessType: shop.business_type
    };

    res.status(200).json({
      message: 'Login successful',
      shop: shopData,
      token: token
    });
  } catch (error) {
    console.error('Login error:', { message: error.message, stack: error.stack });
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Protected route example
app.get('/api/shop/profile', authenticateToken, async (req, res) => {
  try {
    const shopId = req.user.id;
    const [shops] = await pool.query('SELECT id, shop_name, owner_name, email, business_type FROM shops WHERE id = ?', [shopId]);

    if (shops.length === 0) {
      return res.status(404).json({ error: 'Shop not found' });
    }

    res.status(200).json(shops[0]);
  } catch (error) {
    console.error('Profile fetch error:', { message: error.message, stack: error.stack });
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Product Routes
app.get('/api/products', async (req, res) => {
  try {
    const [results] = await pool.query('SELECT * FROM products');
    res.json(results);
  } catch (err) {
    console.error('Error fetching products:', { message: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const [results] = await pool.query('SELECT * FROM products WHERE id = ?', [req.params.id]);
    res.json(results[0] || {});
  } catch (err) {
    console.error('Error fetching product:', { message: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const { name, description, price, image, stock, category } = req.body;
    const [result] = await pool.query(
      'INSERT INTO products (name, description, price, image, stock, category) VALUES (?, ?, ?, ?, ?, ?)',
      [name, description, price, image, stock, category]
    );
    res.json({ id: result.insertId, ...req.body });
  } catch (err) {
    console.error('Error creating product:', { message: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

app.put('/api/products/:id', async (req, res) => {
  try {
    const { name, description, price, image, stock, category } = req.body;
    await pool.query(
      'UPDATE products SET name = ?, description = ?, price = ?, image = ?, stock = ?, category = ? WHERE id = ?',
      [name, description, price, image, stock, category, req.params.id]
    );
    res.json({ message: 'Product updated successfully' });
  } catch (err) {
    console.error('Error updating product:', { message: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM products WHERE id = ?', [req.params.id]);
    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    console.error('Error deleting product:', { message: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// Shop Management Routes
app.get('/api/shop', authenticateToken, async (req, res) => {
  try {
    const user = { ...req.user };
    delete user.password;
    res.json(user);
  } catch (error) {
    console.error('Error fetching shop data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/shop', authenticateToken, async (req, res) => {
  const { shop_name, owner_name, email, phone, address, business_type } = req.body;
  
  if (!shop_name || !owner_name || !email || !business_type) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const [emailCheck] = await pool.query(
      'SELECT id FROM shops WHERE email = ? AND id != ?',
      [email, req.user.id]
    );
    
    if (emailCheck.length > 0) {
      return res.status(400).json({ error: 'Email already in use by another shop' });
    }

    await pool.query(
      `UPDATE shops SET 
        shop_name = ?, 
        owner_name = ?, 
        email = ?, 
        phone = ?, 
        address = ?, 
        business_type = ?,
        updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [shop_name, owner_name, email, phone, address, business_type, req.user.id]
    );

    const [updatedShop] = await pool.query('SELECT * FROM shops WHERE id = ?', [req.user.id]);
    const shopData = { ...updatedShop[0] };
    delete shopData.password;
    
    res.json(shopData);
  } catch (error) {
    console.error('Error updating shop:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/shop/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Both current and new password are required' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    const passwordMatch = await bcrypt.compare(currentPassword, req.user.password);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    await pool.query(
      'UPDATE shops SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [hashedPassword, req.user.id]
    );
    
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Order Routes
app.post('/api/orders', authenticateToken, async (req, res) => {
  const { items, payment_received } = req.body;
  const shop_id = req.user.id;

  try {
    if (!items || !Array.isArray(items)) {
      return res.status(400).json({ error: 'Invalid items data' });
    }

    const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const tax = subtotal * 0.1;
    const total = subtotal + tax;
    const change_amount = payment_received - total;
    const order_number = `ORD-${Date.now()}`;

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      const [orderResult] = await connection.query(
        `INSERT INTO orders 
        (shop_id, order_number, subtotal, tax, total, payment_received, change_amount) 
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [shop_id, order_number, subtotal, tax, total, payment_received, change_amount]
      );

      const order_id = orderResult.insertId;

      for (const item of items) {
        await connection.query(
          `INSERT INTO order_items 
          (order_id, product_id, quantity, unit_price, total_price) 
          VALUES (?, ?, ?, ?, ?)`,
          [order_id, item.id, item.quantity, item.price, item.price * item.quantity]
        );

        await connection.query(
          'UPDATE products SET stock = stock - ? WHERE id = ?',
          [item.quantity, item.id]
        );
      }

      await connection.commit();
      connection.release();

      res.status(201).json({
        message: 'Order created successfully',
        order_id,
        order_number,
        subtotal,
        tax,
        total,
        change_amount
      });

    } catch (err) {
      await connection.rollback();
      connection.release();
      throw err;
    }

  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order', details: error.message });
  }
});

// Get all orders for a shop (authenticated)
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const [orders] = await pool.query(
      `SELECT id, order_number, subtotal, tax, total, 
       payment_received, change_amount, status, created_at 
       FROM orders WHERE shop_id = ? ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get all orders (admin view - unauthenticated)
app.get('/api/all-orders', async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT o.*, s.shop_name 
      FROM orders o
      JOIN shops s ON o.shop_id = s.id
      ORDER BY o.created_at DESC
    `);
    
    for (const order of orders) {
      const [items] = await pool.query(`
        SELECT oi.*, p.name as product_name 
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        WHERE oi.order_id = ?
      `, [order.id]);
      order.items = items;
    }

    res.json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const [orders] = await pool.query(
      `SELECT id, order_number, subtotal, tax, total, 
       payment_received, change_amount, status, created_at 
       FROM orders WHERE id = ? AND shop_id = ?`,
      [req.params.id, req.user.id]
    );

    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const [items] = await pool.query(
      `SELECT oi.id, oi.product_id, p.name, oi.quantity, 
       oi.unit_price, oi.total_price 
       FROM order_items oi
       JOIN products p ON oi.product_id = p.id
       WHERE oi.order_id = ?`,
      [req.params.id]
    );

    res.json({
      ...orders[0],
      items
    });

  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Sales Analytics Routes
app.get('/api/sales/summary', authenticateToken, async (req, res) => {
  try {
    const [todaySales] = await pool.query(
      `SELECT IFNULL(SUM(total), 0) as total_sales, 
       COUNT(id) as order_count 
       FROM orders 
       WHERE shop_id = ? AND DATE(created_at) = CURDATE()`,
      [req.user.id]
    );

    const [weeklySales] = await pool.query(
      `SELECT IFNULL(SUM(total), 0) as total_sales, 
       COUNT(id) as order_count 
       FROM orders 
       WHERE shop_id = ? AND YEARWEEK(created_at, 1) = YEARWEEK(CURDATE(), 1)`,
      [req.user.id]
    );

    const [monthlySales] = await pool.query(
      `SELECT IFNULL(SUM(total), 0) as total_sales, 
       COUNT(id) as order_count 
       FROM orders 
       WHERE shop_id = ? AND MONTH(created_at) = MONTH(CURDATE()) 
       AND YEAR(created_at) = YEAR(CURDATE())`,
      [req.user.id]
    );

    const [topProducts] = await pool.query(
      `SELECT p.id, p.name, SUM(oi.quantity) as total_quantity, 
       SUM(oi.total_price) as total_sales 
       FROM order_items oi
       JOIN products p ON oi.product_id = p.id
       JOIN orders o ON oi.order_id = o.id
       WHERE o.shop_id = ?
       GROUP BY p.id, p.name
       ORDER BY total_quantity DESC
       LIMIT 5`,
      [req.user.id]
    );

    res.json({
      today: todaySales[0],
      weekly: weeklySales[0],
      monthly: monthlySales[0],
      top_products: topProducts
    });

  } catch (error) {
    console.error('Error fetching sales summary:', error);
    res.status(500).json({ error: 'Failed to fetch sales summary' });
  }
});


// Get top products report
app.get('/api/sales/top-products', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    let query = `
      SELECT p.id, p.name, SUM(oi.quantity) as total_quantity, 
      SUM(oi.total_price) as total_sales 
      FROM order_items oi
      JOIN products p ON oi.product_id = p.id
      JOIN orders o ON oi.order_id = o.id
      WHERE o.shop_id = ?
    `;

    const params = [req.user.id];

    if (start_date && end_date) {
      query += ' AND DATE(o.created_at) BETWEEN ? AND ?';
      params.push(start_date, end_date);
    }

    query += `
      GROUP BY p.id, p.name
      ORDER BY total_quantity DESC
      LIMIT 10
    `;

    const [results] = await pool.query(query, params);
    res.json(results);
  } catch (error) {
    console.error('Error fetching top products:', error);
    res.status(500).json({ error: 'Failed to fetch top products' });
  }
});

// Get orders report
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    let query = `
      SELECT id, order_number, subtotal, tax, total, 
      payment_received, change_amount, status, created_at 
      FROM orders WHERE shop_id = ?
    `;

    const params = [req.user.id];

    if (start_date && end_date) {
      query += ' AND DATE(created_at) BETWEEN ? AND ?';
      params.push(start_date, end_date);
    }

    query += ' ORDER BY created_at DESC';

    const [orders] = await pool.query(query, params);
    
    // Get order items for each order
    for (const order of orders) {
      const [items] = await pool.query(
        `SELECT oi.id, oi.product_id, p.name, oi.quantity, 
         oi.unit_price, oi.total_price 
         FROM order_items oi
         JOIN products p ON oi.product_id = p.id
         WHERE oi.order_id = ?`,
        [order.id]
      );
      order.items = items;
    }

    res.json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Unified error handler
app.use((err, req, res, next) => {
  console.error('Global error handler:', { message: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', { message: err.message, stack: err.stack });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});