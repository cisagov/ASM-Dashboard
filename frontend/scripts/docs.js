import serverless from 'serverless-http';
import express from 'express';
import path from 'path';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import helmet from 'helmet';
import fs from 'fs';

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

//Middleware to set Cache-Control headers
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  next();
});

app.use((req, res, next) => {
  res.setHeader('X-XSS-Protection', '0');
  next();
});

// Serve static assets
app.use(
  express.static(path.join(__dirname, '../docs-build'), {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.js')) {
        res.setHeader('Content-Type', 'application/javascript');
      }
    }
  })
);

// Fallback to index.html for client-side routing
app.get('*', (req, res) => {
  const rootDir = path.resolve(__dirname, '../docs-build');
  const staticFilePath = path.resolve(rootDir, '.' + req.path);

  // Check that the file path is under the root directory
  if (!staticFilePath.startsWith(rootDir)) {
    res.status(403).send('Forbidden');
    return;
  }

  // Serve the file if it exists
  if (fs.existsSync(staticFilePath) && fs.lstatSync(staticFilePath).isFile()) {
    res.sendFile(staticFilePath);
  } else {
    // Fallback to index.html for client-side routing
    res.sendFile(path.join(rootDir, 'index.html'));
  }
});

export const handler = serverless(app, {
  binary: ['image/*', 'font/*']
});
