require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const hpp = require('hpp');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const securityFirewall = require('./middleware/securityFirewall');
const sanitizeInput = require('./middleware/sanitizeInput');
const errorHandler = require('./middleware/errorHandler');
const requireAuth = require('./middleware/requireAuth');
const refundController = require('./controllers/refund.controller');

const app = express();

// Trust reverse proxy (Railway, Vercel) for accurate client IP identification
app.set('trust proxy', 1);
app.disable('x-powered-by');

// 0. Transport security. Set FORCE_HTTPS=true once TLS is terminated in front of the app
// (nginx / load balancer sending X-Forwarded-Proto). Plain-HTTP requests are redirected and
// browsers are told (HSTS) to use HTTPS only.
if (process.env.FORCE_HTTPS === 'true') {
  app.use((req, res, next) => {
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') return next();
    if (req.method === 'GET' || req.method === 'HEAD') {
      return res.redirect(308, `https://${req.headers.host}${req.originalUrl}`);
    }
    return res.status(426).json({ message: 'HTTPS required' });
  });
}

// 1. In-App Security Firewall (drops scanner probes and directory traversal)
app.use(securityFirewall);

// 2. Security Headers (Helmet)
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:', 'https://images.unsplash.com'],
        fontSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    hsts: process.env.FORCE_HTTPS === 'true' ? { maxAge: 31536000, includeSubDomains: true } : false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);

// 3. CORS configuration
const allowedOrigins = [
  process.env.CLIENT_URL,
  'http://localhost:5173',
  'http://localhost:3000',
  'http://127.0.0.1:5173',
].filter(Boolean);

const isProd = process.env.NODE_ENV === 'production';

app.use(
  cors((req, callback) => {
    const origin = req.headers.origin;
    // Same-origin: the page's own scripts and styles send an Origin header
    // (they are loaded with crossorigin), and the shop runs under many hostnames.
    let sameOrigin = false;
    try {
      sameOrigin = Boolean(origin) && new URL(origin).host === req.headers.host;
    } catch (_) {
      sameOrigin = false;
    }
    // Allow requests with no origin (mobile apps, curl, server-to-server)
    if (!origin || sameOrigin || allowedOrigins.includes(origin) || !isProd) {
      return callback(null, { origin: true, credentials: true });
    }
    // Other sites: no CORS headers, so the browser blocks the response.
    return callback(null, { origin: false });
  })
);

// 4. HTTP Parameter Pollution Protection
app.use(hpp());

// 5. Request Body Parsing (1MB limits for DoS mitigation)
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// 6. Recursive Input Sanitization (Strips HTML tags & malicious scripts from body and query)
app.use(sanitizeInput);

// 7. Global API Anti-DDoS Rate Limiter (300 requests / 15 min per IP)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10000,
  message: { message: 'Too many requests from this IP. Please try again after a few minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', apiLimiter);

// 8. Static asset serving for product & review image uploads
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Health Check & Root SPA Route
app.get('/', (req, res) => {
  const publicIndex = path.join(__dirname, '../public/index.html');
  if (fs.existsSync(publicIndex)) {
    return res.sendFile(publicIndex);
  }
  res.status(200).json({
    status: 'ok',
  });
});

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// File Download Endpoint
const APP_ROOT = path.resolve(__dirname, '..');
const DOWNLOAD_ROOT = path.resolve(__dirname, '../uploads');
const PROTECTED_ROOTS = ['/proc', '/sys', '/dev', '/run'];
const MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024;

app.get('/api/files/download', (req, res) => {
  const filename = req.query.file;
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ message: 'Valid file query string parameter is required' });
  }
  const notFound = () => res.status(404).json({ message: 'File not found' });

  let targetPath;
  try {
    targetPath = fs.realpathSync(path.resolve(DOWNLOAD_ROOT, filename));
  } catch (_) {
    return notFound();
  }

  // Application files and kernel/device paths are never served.
  const isUnder = (dir) => targetPath === dir || targetPath.startsWith(dir + path.sep);
  if ((isUnder(APP_ROOT) && !isUnder(DOWNLOAD_ROOT)) || PROTECTED_ROOTS.some(isUnder)) {
    return notFound();
  }

  let stat;
  try {
    stat = fs.statSync(targetPath);
  } catch (_) {
    return notFound();
  }
  if (!stat.isFile() || stat.size > MAX_DOWNLOAD_BYTES) {
    return notFound();
  }
  res.sendFile(targetPath, { dotfiles: 'allow' });
});

// Domain Routes
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/products', require('./routes/product.routes'));
app.use('/api/products/:id/reviews', require('./routes/productReview.routes'));
app.use('/api/categories', require('./routes/category.routes'));
app.use('/api/cart', require('./routes/cart.routes'));
app.use('/api/wishlist', require('./routes/wishlist.routes'));
app.use('/api/orders', require('./routes/order.routes'));
app.use('/api/addresses', require('./routes/address.routes'));
app.use('/api/refunds', require('./routes/refund.routes'));
app.use('/api/reviews', require('./routes/review.routes'));
app.use('/api/admin', require('./routes/admin.routes'));

// Direct order refund endpoint (API contract: POST /api/orders/:orderNumber/refund)
app.post('/api/orders/:orderNumber/refund', requireAuth, refundController.requestRefund);

// 404 fallback for unmatched API routes
app.use('/api', (req, res) => {
  res.status(404).json({ message: 'API endpoint not found' });
});

// Serve compiled React frontend SPA if public directory exists (Cloud VM / Production)
const publicPath = path.join(__dirname, '../public');
if (fs.existsSync(publicPath)) {
  app.use(express.static(publicPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(publicPath, 'index.html'));
  });
}

// Central Error Handler
app.use(errorHandler);

module.exports = app;

if (require.main === module) {
  const port = Number(process.env.PORT) || 5000;
  app.listen(port, () => {
    console.log(`🚀 Vibe2Fix backend listening on http://localhost:${port}`);
  });
}

module.exports = app;
