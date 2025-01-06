import serverless from 'serverless-http';
import express from 'express';
import path from 'path';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import helmet from 'helmet';
import fs from 'fs';

export const app = express();

// Rate limiting
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000 // Limit each IP to 1000 requests per windowMs
  })
);

// Serve static assets with explicit MIME types
app.use(
  express.static(path.join(__dirname, '../docs-build'), {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.js')) {
        res.setHeader('Content-Type', 'application/javascript');
      } else if (filePath.endsWith('.css')) {
        res.setHeader('Content-Type', 'text/css');
      }
    }
  })
);

// CORS settings
app.use(
  cors({
    origin: [
      /^https:\/\/(.*\.)?crossfeed\.cyber\.dhs\.gov$/,
      /^https:\/\/(.*\.)?readysetcyber\.cyber\.dhs\.gov$/
    ],
    methods: 'GET,POST,PUT,DELETE,OPTIONS'
  })
);

// Helmet for security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          'https://ajax.googleapis.com',
          'https://www.ssa.gov'
        ],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https://www.ssa.gov'],
        frameSrc: ["'self'", 'https://www.dhs.gov/ntas/'],
        objectSrc: ["'none'"]
      }
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  })
);

// Middleware to set Cache-Control headers
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  next();
});

// Middleware to disable XSS protection
app.use((req, res, next) => {
  res.setHeader('X-XSS-Protection', '0');
  next();
});

// Route to serve `/docs` directly
app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, '../docs-build/index.html'));
});

// Route to serve `/docs/*` for Gatsby client-side routing
app.get('/docs/*', (req, res) => {
  const rootFolder = path.join(__dirname, '../docs-build');
  const requestedPath = req.path.replace('/docs', '');
  const staticFilePath = path.join(rootFolder, requestedPath);

  // Debugging logs for path resolution
  console.log(`Requested path: ${requestedPath}`);
  console.log(`Resolved file path: ${staticFilePath}`);

  // If the requested file exists, serve it
  if (fs.existsSync(staticFilePath) && fs.lstatSync(staticFilePath).isFile()) {
    console.log(`Serving file: ${staticFilePath}`);
    res.sendFile(staticFilePath);
  } else {
    // Fallback to index.html for client-side routing
    console.log(`File not found, falling back to index.html`);
    res.sendFile(path.join(rootFolder, 'index.html'));
  }
});

// Fallback for all other routes (non /docs)
app.get('*', (req, res) => {
  res.status(404).send('Not Found');
});

// Serverless handler
export const handler = serverless(app, {
  binary: ['image/*', 'font/*']
});
