// backend/server.js
import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import rateLimit from "express-rate-limit";
import { body, param, query, validationResult } from "express-validator";
import fs from "fs";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import morgan from "morgan";
import nodemailer from "nodemailer";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

// Config
const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "change_me";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "*";

// Connect DB
async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI);
    console.log("✅ MongoDB Connected...");
  } catch (err) {
    console.error("❌ MongoDB Error:", err.message);
    process.exit(1);
  }
}

// Mongoose Schemas & Models
const { Schema } = mongoose;

const userSchema = new Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ["admin"], default: "admin" },
  },
  { timestamps: true }
);

const productSchema = new Schema(
  {
    name: { type: String, required: true },
    slug: { type: String, required: true, unique: true },
    category: {
      type: String,
      enum: ["import", "export", "chemicals", "coal", "supplies"],
      required: true,
      index: true,
    },
    image: String,
    gallery: [String],
    shortDescription: String,
    description: String,
    specs: [{ key: String, value: String }],
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

const messageSchema = new Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    source: { type: String, default: "web" },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Product = mongoose.model("Product", productSchema);
const Message = mongoose.model("Message", messageSchema);

// Utils
function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(400).json({ errors: errors.array() });
  next();
}

// Auth middleware
function auth(required = true) {
  return (req, res, next) => {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) {
      if (required) return res.status(401).json({ message: "Unauthorized" });
      req.user = null;
      return next();
    }
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      next();
    } catch (e) {
      return res.status(401).json({ message: "Invalid token" });
    }
  };
}

// Nodemailer transport
function getTransport() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: false,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}

// Express App
const app = express();
app.use(helmet());
app.use(express.json({ limit: "2mb" }));
app.use(cors({ origin: CLIENT_ORIGIN }));
app.use(morgan("dev"));

// Rate limiting (messages)
const limiter = rateLimit({ windowMs: 60 * 1000, max: 100 });
app.use("/api/messages", limiter);

// API ROUTES =========================

// Health
app.get("/api/health", (req, res) => res.json({ ok: true }));

// Auth login
app.post(
  "/api/auth/login",
  [body("email").isEmail(), body("password").isLength({ min: 6 })],
  handleValidation,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user) return res.status(401).json({ message: "Invalid credentials" });

      const ok = await bcrypt.compare(password, user.passwordHash);
      if (!ok) return res.status(401).json({ message: "Invalid credentials" });

      const token = jwt.sign(
        { id: user._id, email: user.email },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      res.json({ token });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Products API
app.get(
  "/api/products",
  [
    query("category")
      .optional()
      .isIn(["import", "export", "chemicals", "coal", "supplies"]),
    query("q").optional().isString(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { category, q } = req.query;
      const filter = {};
      if (category) filter.category = category;
      if (q) filter.name = { $regex: q, $options: "i" };

      const items = await Product.find(filter).sort({ createdAt: -1 });
      res.json(items);
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.get("/api/products/:slug", [param("slug").isString()], handleValidation, async (req, res) => {
  try {
    const item = await Product.findOne({ slug: req.params.slug });
    if (!item) return res.status(404).json({ message: "Product not found" });
    res.json(item);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Server error" });
  }
});

// Add product (admin only)
app.post(
  "/api/products",
  auth(true),
  [
    body("name").notEmpty(),
    body("slug").isSlug(),
    body("category").isIn(["import", "export", "chemicals", "coal", "supplies"]),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const exists = await Product.findOne({ slug: req.body.slug });
      if (exists) return res.status(409).json({ message: "Slug already exists" });

      const product = await Product.create(req.body);
      res.status(201).json(product);
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Messages (contact form)
app.post(
  "/api/messages",
  [
    body("name").trim().notEmpty(),
    body("email").isEmail(),
    body("subject").trim().notEmpty(),
    body("message").trim().isLength({ min: 10 }),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const msg = await Message.create(req.body);

      // Optional email notification
      const to = process.env.MAIL_TO || process.env.SMTP_USER;
      const transport = getTransport();
      if (transport && to) {
        try {
          await transport.sendMail({
            from: process.env.SMTP_USER,
            to,
            subject: "New Contact Message",
            html: `<h2>New Contact Message</h2>
              <p><b>Name:</b> ${msg.name}</p>
              <p><b>Email:</b> ${msg.email}</p>
              <p><b>Subject:</b> ${msg.subject}</p>
              <p><b>Message:</b><br>${msg.message.replace(/\n/g, "<br>")}</p>`,
          });
        } catch (err) {
          console.error("Mail send failed", err);
        }
      }

      res
        .status(201)
        .json({ success: true, message: "Message received", id: msg._id });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// =====================================
// Seed Script
// =====================================
async function seedDatabase() {
  try {
    console.log("🌱 Seeding database...");

    // Seed admin user
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPass = process.env.ADMIN_PASSWORD;
    if (adminEmail && adminPass) {
      const exists = await User.findOne({ email: adminEmail });
      if (!exists) {
        const passwordHash = await bcrypt.hash(adminPass, 10);
        await User.create({
          name: "Admin",
          email: adminEmail,
          passwordHash,
          role: "admin",
        });
        console.log("✅ Admin user created");
      } else {
        console.log("ℹ️ Admin user already exists");
      }
    }

    // Seed sample products
    const sampleProducts = [
      {
        name: "Marble",
        slug: "marble",
        category: "import",
        shortDescription: "High-quality imported marble",
        description: "Perfect for construction and design.",
        image: "https://example.com/marble.jpg",
      },
      {
        name: "Ion Gas",
        slug: "ion-gas",
        category: "export",
        shortDescription: "Industrial ion gas",
        description: "Used in manufacturing and chemical processes.",
        image: "https://example.com/ion-gas.jpg",
      },
      {
        name: "Ethanol",
        slug: "ethanol",
        category: "chemicals",
        shortDescription: "Purified ethanol",
        description: "For labs and industrial use.",
        image: "https://example.com/ethanol.jpg",
      },
    ];

    for (const product of sampleProducts) {
      const exists = await Product.findOne({ slug: product.slug });
      if (!exists) {
        await Product.create(product);
        console.log(`✅ Product created: ${product.name}`);
      }
    }

    console.log("🌱 Seeding done");
  } catch (err) {
    console.error("❌ Seed error:", err.message);
  }
}

// =====================================
// Static Frontend
// =====================================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "public");

if (!fs.existsSync(publicDir)) {
  console.warn("⚠️ ./public does not exist. Create it for your frontend build.");
}
app.use(express.static(publicDir));

// 404 for unknown API
app.use("/api/*", (req, res) =>
  res.status(404).json({ message: "API route not found" })
);

// =====================================
// Start Server
// =====================================
const start = async () => {
  await connectDB();

  if (process.env.SEED === "true") {
    await seedDatabase();
  }

  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
  });
};

start();

