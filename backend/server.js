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
    // Verify token with correct secret
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    console.log('Decoded token:', decoded);
    
    // Use shopId instead of id (matches your token payload)
    const [shops] = await pool.query('SELECT * FROM shops WHERE id = ?', [decoded.shopId]);
    
    if (shops.length === 0) {
      console.log('Shop not found in database');
      return res.sendStatus(403);
    }
    
    req.user = shops[0];
    next();
  } catch (err) {
    console.error('JWT verification error:', err);
    
    // Specific error messages
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

    // Validate input
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

    // Check if email exists
    const [existingShops] = await pool.query('SELECT * FROM shops WHERE email = ?', [email]);
    if (existingShops.length > 0) {
      console.log('Email already in use');
      return res.status(400).json({ error: 'Email already in use' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create shop
    const [result] = await pool.query(
      'INSERT INTO shops (shop_name, owner_name, email, phone, address, password, business_type) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [shopName, ownerName, email, phone, address, hashedPassword, businessType]
    );

    // Create JWT token
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

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Check if shop exists
    const [shops] = await pool.query('SELECT * FROM shops WHERE email = ?', [email]);
    if (shops.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const shop = shops[0];

    // Verify password
    const passwordMatch = await bcrypt.compare(password, shop.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Create JWT token
    const token = jwt.sign(
      { shopId: shop.id, email: shop.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Return shop data (without password) and token
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
    const shopId = req.user.shopId;
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

// Get all products
app.get('/api/products', async (req, res) => {
  try {
    const [results] = await pool.query('SELECT * FROM products');
    res.json(results);
  } catch (err) {
    console.error('Error fetching products:', { message: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const [results] = await pool.query('SELECT * FROM products WHERE id = ?', [req.params.id]);
    res.json(results[0] || {});
  } catch (err) {
    console.error('Error fetching product:', { message: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// Create new product
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

// Update product
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

// Delete product
app.delete('/api/products/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM products WHERE id = ?', [req.params.id]);
    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    console.error('Error deleting product:', { message: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// Get shop data endpoint
app.get('/api/shop', authenticateToken, async (req, res) => {
  try {
    // Return user data without password
    const user = { ...req.user };
    delete user.password;
    res.json(user);
  } catch (error) {
    console.error('Error fetching shop data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update shop profile endpoint
app.put('/api/shop', authenticateToken, async (req, res) => {
  const { shop_name, owner_name, email, phone, address, business_type } = req.body;
  
  // Basic validation
  if (!shop_name || !owner_name || !email || !business_type) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Check if email is already taken by another shop
    const [emailCheck] = await pool.query(
      'SELECT id FROM shops WHERE email = ? AND id != ?',
      [email, req.user.id]
    );
    
    if (emailCheck.length > 0) {
      return res.status(400).json({ error: 'Email already in use by another shop' });
    }

    // Update shop data
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

    // Get updated shop data
    const [updatedShop] = await pool.query('SELECT * FROM shops WHERE id = ?', [req.user.id]);
    
    // Don't send password back
    const shopData = { ...updatedShop[0] };
    delete shopData.password;
    
    res.json(shopData);
  } catch (error) {
    console.error('Error updating shop:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password endpoint
app.put('/api/shop/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Both current and new password are required' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    // Verify current password
    const passwordMatch = await bcrypt.compare(currentPassword, req.user.password);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update password
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

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something broke!' });
});


// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error handler:', { message: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', { message: err.message, stack: err.stack });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});