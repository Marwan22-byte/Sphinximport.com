// ---------------------- IMPORTS ----------------------
import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import morgan from 'morgan';

import bcrypt from 'bcryptjs';
const { hash, compare } = bcrypt;

import jwt from 'jsonwebtoken';
const { sign, verify } = jwt;

import nodemailer from 'nodemailer';

import path from 'path';
import { fileURLToPath } from 'url';

// ---------------------- SETUP ----------------------
dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

// Fix __dirname in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------- MIDDLEWARE ----------------------
app.use(express.json());
app.use(cors());
app.use(helmet());
app.use(morgan('dev'));

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// ---------------------- DATABASE ----------------------
mongoose
  .connect(process.env.MONGO_URI, { dbName: 'sphinxDB' })
  .then(() => console.log('✅ MongoDB Connected'))
  .catch((err) => console.error('❌ MongoDB Error:', err));

// ---------------------- MODELS ----------------------
const productSchema = new mongoose.Schema({
  name: String,
  price: Number,
  description: String,
});

const messageSchema = new mongoose.Schema({
  name: String,
  email: String,
  message: String,
});

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const Product = mongoose.model('Product', productSchema);
const Message = mongoose.model('Message', messageSchema);
const User = mongoose.model('User', userSchema);

// ---------------------- AUTH MIDDLEWARE ----------------------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ---------------------- ROUTES ----------------------

// Root
app.get('/', (req, res) => {
  res.send('🌍 Welcome to Sphinx Company API');
});

// Products
app.get('/products', async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

app.post('/products', authenticateToken, async (req, res) => {
  const product = new Product(req.body);
  await product.save();
  res.json(product);
});

// Messages (Contact Form)
app.post(
  '/messages',
  body('email').isEmail(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const message = new Message(req.body);
    await message.save();
    res.json({ message: '📩 Message saved successfully!' });
  }
);

// Admin Register (only for setup)
app.post('/admin/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();
  res.json({ message: '✅ Admin registered successfully' });
});

// Admin Login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) return res.status(400).json({ error: 'User not found' });

  const validPassword = await compare(password, user.password);
  if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

  const token = sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// ---------------------- STATIC FRONTEND ----------------------
app.use(express.static(path.join(__dirname, 'Frontend')));

// ---------------------- START SERVER ----------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});



