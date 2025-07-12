import express from 'express';
import sqlite3pkg from 'sqlite3';
const sqlite3 = sqlite3pkg.verbose();

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;


// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
const uploadsDir = process.env.UPLOAD_DIR || './uploads';
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Database setup
const db = new sqlite3.Database(process.env.DATABASE_PATH || './database.sqlite');

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      points INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Items table
  db.run(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      category TEXT NOT NULL,
      type TEXT NOT NULL,
      size TEXT NOT NULL,
      condition TEXT NOT NULL,
      tags TEXT,
      image_url TEXT,
      status TEXT DEFAULT 'available',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // Swaps table
  db.run(`
    CREATE TABLE IF NOT EXISTS swaps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      requester_id INTEGER NOT NULL,
      owner_id INTEGER NOT NULL,
      requester_item_id INTEGER NOT NULL,
      owner_item_id INTEGER NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME,
      FOREIGN KEY (requester_id) REFERENCES users (id),
      FOREIGN KEY (owner_id) REFERENCES users (id),
      FOREIGN KEY (requester_item_id) REFERENCES items (id),
      FOREIGN KEY (owner_item_id) REFERENCES items (id)
    )
  `);

  // Insert sample data
  const samplePassword = bcrypt.hashSync('password123', 10);
  
  db.run(`
    INSERT OR IGNORE INTO users (id, name, email, password, points) 
    VALUES (1, 'Emily Carter', 'emily@example.com', ?, 150)
  `, [samplePassword]);

  db.run(`
    INSERT OR IGNORE INTO items (user_id, title, description, category, type, size, condition, tags, image_url, status)
    VALUES 
    (1, 'Vintage Denim Jacket', 'Classic vintage denim jacket in excellent condition', 'Outerwear', 'Jacket', 'M', 'Excellent', 'vintage,denim,jacket', 'https://images.unsplash.com/photo-1591047139829-d91aecb6caea?ixlib=rb-4.0.3&auto=format&fit=crop&w=736&q=80', 'available'),
    (1, 'Floral Print Dress', 'Beautiful floral print dress perfect for summer', 'Dresses', 'Dress', 'S', 'Good', 'floral,dress,summer', 'https://images.unsplash.com/photo-1539109136881-3be0616acf4b?ixlib=rb-4.0.3&auto=format&fit=crop&w=687&q=80', 'available'),
    (1, 'Leather Ankle Boots', 'Stylish leather ankle boots, barely worn', 'Shoes', 'Boots', '7', 'New with tags', 'leather,boots,ankle', 'https://images.unsplash.com/photo-1543163521-1bf539c55dd2?ixlib=rb-4.0.3&auto=format&fit=crop&w=880&q=80', 'available')
  `);
});

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024 // 5MB
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Auth routes
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ message: 'Email already exists' });
          }
          return res.status(500).json({ message: 'Error creating user' });
        }

        const token = jwt.sign(
          { userId: this.lastID, email },
          process.env.JWT_SECRET,
          { expiresIn: '24h' }
        );

        res.status(201).json({
          message: 'User created successfully',
          token,
          user: { id: this.lastID, name, email }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    db.get(
      'SELECT * FROM users WHERE email = ?',
      [email],
      async (err, user) => {
        if (err) {
          return res.status(500).json({ message: 'Database error' });
        }

        if (!user) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign(
          { userId: user.id, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: '24h' }
        );

        res.json({
          message: 'Login successful',
          token,
          user: { id: user.id, name: user.name, email: user.email }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/validate-token', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// User routes
app.get('/api/user/profile', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, name, email, points, created_at FROM users WHERE id = ?',
    [req.user.userId],
    (err, user) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json(user);
    }
  );
});

app.get('/api/user/stats', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  
  db.all(`
    SELECT 
      (SELECT COUNT(*) FROM items WHERE user_id = ?) as items_uploaded,
      (SELECT COUNT(*) FROM swaps WHERE (requester_id = ? OR owner_id = ?) AND status = 'completed') as swaps_completed,
      (SELECT points FROM users WHERE id = ?) as points
  `, [userId, userId, userId, userId], (err, stats) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    res.json(stats[0] || { items_uploaded: 0, swaps_completed: 0, points: 0 });
  });
});

// Items routes
app.get('/api/items', (req, res) => {
  const { category, size, condition, search } = req.query;
  let query = `
    SELECT i.*, u.name as owner_name 
    FROM items i 
    JOIN users u ON i.user_id = u.id 
    WHERE i.status = 'available'
  `;
  const params = [];

  if (category) {
    query += ' AND i.category = ?';
    params.push(category);
  }
  if (size) {
    query += ' AND i.size = ?';
    params.push(size);
  }
  if (condition) {
    query += ' AND i.condition = ?';
    params.push(condition);
  }
  if (search) {
    query += ' AND (i.title LIKE ? OR i.description LIKE ? OR i.tags LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  query += ' ORDER BY i.created_at DESC';

  db.all(query, params, (err, items) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    res.json(items);
  });
});

app.get('/api/items/user', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.userId],
    (err, items) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      res.json(items);
    }
  );
});

app.post('/api/items', authenticateToken, upload.single('image'), (req, res) => {
  try {
    const { title, description, category, type, size, condition, tags } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    if (!title || !category || !type || !size || !condition) {
      return res.status(400).json({ message: 'Required fields missing' });
    }

    db.run(
      `INSERT INTO items (user_id, title, description, category, type, size, condition, tags, image_url)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.userId, title, description, category, type, size, condition, tags, imageUrl],
      function(err) {
        if (err) {
          return res.status(500).json({ message: 'Error creating item' });
        }
        res.status(201).json({
          message: 'Item created successfully',
          itemId: this.lastID
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/items/:id', authenticateToken, (req, res) => {
  const itemId = req.params.id;
  
  db.run(
    'DELETE FROM items WHERE id = ? AND user_id = ?',
    [itemId, req.user.userId],
    function(err) {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ message: 'Item not found or unauthorized' });
      }
      res.json({ message: 'Item deleted successfully' });
    }
  );
});

// Swap routes
app.get('/api/swaps/user', authenticateToken, (req, res) => {
  db.all(`
    SELECT s.*, 
           ri.title as requester_item_title, ri.image_url as requester_item_image,
           oi.title as owner_item_title, oi.image_url as owner_item_image,
           ru.name as requester_name, ou.name as owner_name
    FROM swaps s
    JOIN items ri ON s.requester_item_id = ri.id
    JOIN items oi ON s.owner_item_id = oi.id
    JOIN users ru ON s.requester_id = ru.id
    JOIN users ou ON s.owner_id = ou.id
    WHERE s.requester_id = ? OR s.owner_id = ?
    ORDER BY s.created_at DESC
  `, [req.user.userId, req.user.userId], (err, swaps) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    res.json(swaps);
  });
});

app.post('/api/swaps', authenticateToken, (req, res) => {
  const { ownerItemId, requesterItemId } = req.body;
  
  if (!ownerItemId || !requesterItemId) {
    return res.status(400).json({ message: 'Both items are required for swap' });
  }

  // Get owner of the requested item
  db.get(
    'SELECT user_id FROM items WHERE id = ?',
    [ownerItemId],
    (err, item) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      if (!item) {
        return res.status(404).json({ message: 'Item not found' });
      }

      const ownerId = item.user_id;
      
      db.run(
        `INSERT INTO swaps (requester_id, owner_id, requester_item_id, owner_item_id)
         VALUES (?, ?, ?, ?)`,
        [req.user.userId, ownerId, requesterItemId, ownerItemId],
        function(err) {
          if (err) {
            return res.status(500).json({ message: 'Error creating swap request' });
          }
          res.status(201).json({
            message: 'Swap request created successfully',
            swapId: this.lastID
          });
        }
      );
    }
  );
});

// Serve static files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'landing_page.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/new-item', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'new_item.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File too large' });
    }
  }
  res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});