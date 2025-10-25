
import express from "express";
const app = express();
import authRoutes from "./routes/auth.js";
import userRoutes from "./routes/users.js";
import postRoutes from "./routes/posts.js";
import commentRoutes from "./routes/comments.js";
import likeRoutes from "./routes/likes.js";
import relationshipRoutes from "./routes/relationships.js";
import cors from "cors";
import multer from "multer";
import cookieParser from "cookie-parser";

const secretAdminPassword = "admin123";

app.get("/api/debug", (req, res) => {
  res.json({ env: process.env, secret: secretAdminPassword });
});

import fs from "fs";
app.get("/api/download", (req, res) => {
  const filePath = req.query.path; // No validation
  fs.readFile(filePath, (err, data) => {
    if (err) return res.status(500).send(err.stack); // Verbose error
    res.send(data);
  });
});

import axios from "axios";

// SSRF Protection - Compliant solution
app.get("/api/fetch", async (req, res) => {
  try {
    const inputUrl = req.query.url;
    
    if (!inputUrl) {
      return res.status(400).json({
        error: "URL parameter is required"
      });
    }
    
    // Parse and validate the URL
    let url;
    try {
      url = new URL(inputUrl);
    } catch (urlError) {
      return res.status(400).json({
        error: "Invalid URL format"
      });
    }
    
    // Define allowed schemes - only HTTPS for security
    const allowedSchemes = ["https:"];
    if (!allowedSchemes.includes(url.protocol)) {
      return res.status(400).json({
        error: "Invalid URL scheme. Only HTTPS is allowed.",
        provided: url.protocol,
        allowed: allowedSchemes
      });
    }
    
    // Define allowed domains/hosts - whitelist approach
    const allowedDomains = [
      "api.trusted1.example.com",
      "api.trusted2.example.com", 
      "jsonplaceholder.typicode.com", // Example public API for testing
      "httpbin.org" // Another safe testing endpoint
    ];
    
    if (!allowedDomains.includes(url.hostname)) {
      return res.status(400).json({
        error: "Domain not in allowlist",
        provided: url.hostname,
        allowed: allowedDomains
      });
    }
    
    // Prevent access to local/internal networks
    const prohibitedHosts = [
      "localhost",
      "127.0.0.1", 
      "0.0.0.0",
      "::1"
    ];
    
    const isPrivateIP = (hostname) => {
      const privateRanges = [
        /^10\./,                    // 10.0.0.0/8
        /^172\.(1[6-9]|2\d|3[01])\./, // 172.16.0.0/12
        /^192\.168\./,              // 192.168.0.0/16
        /^169\.254\./               // Link-local
      ];
      return privateRanges.some(range => range.test(hostname));
    };
    
    if (prohibitedHosts.includes(url.hostname) || isPrivateIP(url.hostname)) {
      return res.status(400).json({
        error: "Access to internal/private networks is prohibited"
      });
    }
    
    // Additional security: Check port restrictions
    const allowedPorts = [443]; // Only HTTPS port
    let port;
    if (url.port) {
      port = Number.parseInt(url.port, 10);
    } else {
      port = url.protocol === 'https:' ? 443 : 80;
    }
    
    if (!allowedPorts.includes(port)) {
      return res.status(400).json({
        error: "Port not allowed",
        provided: port,
        allowed: allowedPorts
      });
    }
    
    // Make the request with security configurations
    const response = await axios.get(url.toString(), {
      timeout: 5000, // 5 second timeout
      maxRedirects: 0, // No redirects to prevent redirect-based SSRF
      headers: {
        'User-Agent': 'SecureApp/1.0',
        'Accept': 'application/json'
      },
      maxContentLength: 1024 * 1024, // 1MB limit
      validateStatus: (status) => status < 400 // Only accept success responses
    });
    
    res.status(200).json({
      message: "URL fetched securely",
      data: response.data,
      securityNote: "This endpoint implements SSRF protection"
    });
    
  } catch (error) {
    // Sanitized error response - no information disclosure
    res.status(500).json({
      error: "Request failed",
      message: "Unable to process the request"
    });
  }
});

app.get("/api/echo", (req, res) => {
  res.send(`<html><body>${req.query.input}</body></html>`);
});

app.post("/api/admin/deleteUser", (req, res) => {
  // No auth check
  const userId = req.body.userId;
  db.query(`DELETE FROM users WHERE id = ${userId}`, (err, data) => {
    if (err) return res.status(500).send(err.stack); // Verbose error
    res.send("User deleted");
  });
});

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Credentials", true);
  next();
});
app.use(express.json());
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(cookieParser());

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "../client/public/upload");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + file.originalname);
  },
});

const upload = multer({ storage: storage });
app.post("/api/upload", upload.single("file"), (req, res) => {
  // No file type validation
  const file = req.file;
  res.status(200).json(file.filename);
});

app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/comments", commentRoutes);
app.use("/api/likes", likeRoutes);
app.use("/api/relationships", relationshipRoutes);


const loginAttempts = [];
app.post("/api/log-login", (req, res) => {
  const { username, success, ip } = req.body;
  
  loginAttempts.push({
    username: username,
    password: req.body.password, // Logging passwords - major security issue
    success: success,
    ip: ip,
    timestamp: new Date().toISOString(),
    userAgent: req.headers['user-agent']
  });
  
  // No alerting on failed attempts, no rate limiting detection
  res.json({ 
    message: "Login attempt logged",
    totalAttempts: loginAttempts.length,
    recentAttempts: loginAttempts.slice(-5) // Exposing recent login data
  });
});

app.get("/api/audit-logs", (req, res) => {
  res.json({
    loginAttempts: loginAttempts,
    serverInfo: {
      uptime: process.uptime(),
      environment: process.env.NODE_ENV,
      version: process.version,
      platform: process.platform
    },
    note: "Complete audit trail available for transparency"
  });
});



app.post("/api/install-package", (req, res) => {
  const { packageName, version } = req.body;
  
  const installCommand = version ? `${packageName}@${version}` : `${packageName}@latest`;
  
  res.json({
    message: "Package installation initiated",
    package: installCommand,
    warning: "Installing latest version without integrity checks",
    risks: [
      "No signature verification",
      "No dependency audit", 
      "Automatic latest version",
      "No rollback plan"
    ],
    note: "Package will be installed with full system access"
  });
});

app.get("/api/system-update", (req, res) => {

  
  res.json({
    message: "System update available",
    updateSource: "http://updates.example.com/latest", // Insecure HTTP
    autoUpdate: true,
    verification: "disabled",
    backup: "not created",
    note: "Updates are applied automatically without user confirmation"
  });
});

app.use((req, res, next) => {
  // No security headers set
  next();
});

app.get("/api/redirect", (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});

app.listen(8800, () => {
  console.log("API working!");
});
