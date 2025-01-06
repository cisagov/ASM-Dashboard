import serverless from 'serverless-http';
import express from 'express';
import path from 'path';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import helmet from 'helmet';

export const app = express();

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000
  })
); // limit 1000 requests per 15 minutes

app.use(express.static(path.join(__dirname, '../docs/build')));

app.use(
  cors({
    origin: [
      /^https:\/\/(.*\.)?crossfeed\.cyber\.dhs\.gov$/,
      /^https:\/\/(.*\.)?readysetcyber\.cyber\.dhs\.gov$/
    ],
    methods: 'GET,POST,PUT,DELETE,OPTIONS'
  })
);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: [
          "'self'",
          `${process.env.COGNITO_URL}`,
          `${process.env.BACKEND_DOMAIN}`
        ],
        frameSrc: ["'self'", 'https://www.dhs.gov/ntas/'],
        imgSrc: [
          "'self'",
          'data:',
          `https://${process.env.DOMAIN}`,
          'https://www.ssa.gov',
          'https://www.dhs.gov'
        ],
        objectSrc: ["'none'"],
        scriptSrc: [
          "'self'",
          `${process.env.BACKEND_DOMAIN}`,
          'https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js',
          'https://www.ssa.gov/accessibility/andi/fandi.js',
          'https://www.ssa.gov/accessibility/andi/andi.js',
          'https://www.dhs.gov'
        ],
        frameAncestors: ["'none'"]
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

// Explicitly handle `/docs` route
app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, '../docs-build/index.html'));
});

// Fallback to index.html for Gatsby routing
app.get('/docs/*', (req, res) => {
  res.sendFile(path.join(__dirname, '../docs-build/index.html'));
});

// Explicitly handle `/docs` route
app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, '../docs-build/index.html'));
});

// Fallback for all other routes
app.get('*', (req, res) => {
  const staticFilePath = path.join(__dirname, '../docs-build', req.path);

  // Serve static file if it exists
  if (fs.existsSync(staticFilePath) && fs.lstatSync(staticFilePath).isFile()) {
    res.sendFile(staticFilePath);
  } else {
    // Otherwise fallback to index.html for client-side routing
    res.sendFile(path.join(__dirname, '../docs-build/index.html'));
  }
});

export const handler = serverless(app, {
  binary: ['image/*', 'font/*']
});
