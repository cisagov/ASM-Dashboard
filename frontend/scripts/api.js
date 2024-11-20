// Main entrypoint for serverless frontend code.

import serverless from 'serverless-http';
import cors from 'cors';
import helmet from 'helmet';
import express from 'express';
import path from 'path';

export const app = express();

app.use((req, res, next) => {
  const sanitizedHeaders = { ...req.headers };
  // Remove or replace sensitive headers
  delete sanitizedHeaders['authorization'];
  console.log(`Request Headers: ${JSON.stringify(sanitizedHeaders)}`);
  next();
});

// These CORS origins work in all Crossfeed environments
app.use(
  cors({
    origin: [
      /^https:\/\/(.*\.)?crossfeed\.cyber\.dhs\.gov$/,
      /^https:\/\/(.*\.)?readysetcyber\.cyber\.dhs\.gov$/
    ],
    methods: 'GET,POST,PUT,DELETE,OPTIONS'
  })
);

// The API URLs are different in each environment
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

app.use(
  express.static(path.join(__dirname, '../build'), {
    setHeaders: (res, path) => {
      if (path.endsWith('.js')) {
        res.setHeader('Content-Type', 'application/javascript');
      }
    },
    maxAge: 'no-cache, no-store, must-revalidate'
  })
);

app.use((req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.sendFile(path.join(__dirname, '../build/index.html'));
});

export const handler = serverless(app, {
  binary: ['image/*', 'font/*']
});
