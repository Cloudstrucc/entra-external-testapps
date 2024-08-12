require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse JSON payloads
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Configure passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Passport serialization
passport.serializeUser((user, done) => {
  console.log('Serializing user:', user);
  done(null, user);
});

passport.deserializeUser((user, done) => {
  console.log('Deserializing user:', user);
  done(null, user);
});

// Function to pretty print JWT
function prettyPrintJwt(token) {
  try {
    const decoded = jwt.decode(token, { complete: true });
    return JSON.stringify(decoded, null, 2);
  } catch (error) {
    console.error('Error decoding JWT:', error);
    return 'Invalid JWT';
  }
}

// Function to extract email from token payload
function extractEmailFromToken(token) {
  try {
    const decoded = jwt.decode(token);
    console.log('Decoded token:', JSON.stringify(decoded, null, 2));
    if (decoded.unique_name && decoded.unique_name.includes('@')) {
      return decoded.unique_name;
    }
    if (decoded.upn && decoded.upn.includes('@')) {
      return decoded.upn;
    }
    console.log('No email found in token');
    return null;
  } catch (error) {
    console.error('Error decoding token:', error);
    return null;
  }
}

// Configure OIDC strategy
passport.use(new OIDCStrategy({
  identityMetadata: `https://cloudstruccentradev.ciamlogin.com/${process.env.TENANT_ID}/v2.0/.well-known/openid-configuration`,
  clientID: process.env.CLIENT_ID,
  responseType: 'code',
  responseMode: 'query',
  redirectUrl: process.env.REDIRECT_URI,
  allowHttpForRedirectUrl: true,
  clientSecret: process.env.CLIENT_SECRET,
  validateIssuer: false,
  passReqToCallback: true,
  scope: ['openid', 'profile', 'email', 'offline_access']
}, async (req, iss, sub, profile, accessToken, refreshToken, params, done) => {
  console.log('OIDC Strategy Callback:');
  console.log('Issuer:', iss);
  console.log('Subject:', sub);
  console.log('Profile:', JSON.stringify(profile, null, 2));
  console.log('Access Token:', accessToken ? 'Present' : 'Not present');
  console.log('Refresh Token:', refreshToken ? 'Present' : 'Not present');
  console.log('Params:', JSON.stringify(params, null, 2));

  if (!profile.oid) {
    console.error('No OID found in profile');
    return done(new Error("No OID found"), null);
  }

  const email = extractEmailFromToken(accessToken);

  const user = {
    oid: profile.oid,
    email: email,
    displayName: profile.displayName || profile.name || 'Unknown',
    accessToken: accessToken,
    refreshToken: refreshToken
  };

  console.log('User object created:', user);

  return done(null, user);
}));

// Define routes
app.get('/', (req, res) => {
  res.send('<a href="/login">Login</a> | <a href="/status">Check Status</a>');
});

app.get('/login', (req, res, next) => {
  console.log('Login route accessed');
  passport.authenticate('azuread-openidconnect', {
    failureRedirect: '/',
    failureFlash: true
  })(req, res, next);
});

app.get('/auth/openid/return', (req, res, next) => {
  console.log('Auth return route accessed');
  console.log('Query params:', req.query);
  passport.authenticate('azuread-openidconnect', {
    failureRedirect: '/',
    failureFlash: true
  })(req, res, (err, user, info) => {
    if (err) {
      console.error('Authentication error:', err);
      return next(err);
    }
    if (!user) {
      console.error('Authentication failed:', info);
      return res.redirect('/');
    }
    console.log('Authentication successful. User:', user);
    console.log('Authentication info:', info);
    req.logIn(user, (err) => {
      if (err) {
        console.error('Login error:', err);
        return next(err);
      }
      console.log('Login successful. Redirecting to profile page.');
      res.redirect('/profile');
    });
  });
});

app.get('/profile', async (req, res) => {
  console.log('Profile route accessed. User:', req.user);
  if (!req.isAuthenticated()) {
    return res.status(401).send('Unauthorized: No user logged in');
  }

  res.json({
    message: `Welcome, ${req.user.displayName || req.user.email || 'User'}!`,
    profile: {
      oid: req.user.oid,
      email: req.user.email || 'Email not available',
      displayName: req.user.displayName || 'N/A'
    }
  });
});

// Debug route to display the access token
app.get('/debug/token', (req, res) => {
  console.log('Debug token route accessed. User:', req.user);
  if (!req.isAuthenticated()) {
    return res.status(401).send('Unauthorized: No user logged in');
  }
  if (!req.user.accessToken) {
    return res.status(400).send('No access token available in user object');
  }
  res.send(`<pre>${prettyPrintJwt(req.user.accessToken)}</pre>`);
});

// Route to check current authentication status
app.get('/status', (req, res) => {
  console.log('Status route accessed. Is authenticated:', req.isAuthenticated());
  console.log('User:', req.user);
  res.json({
    authenticated: req.isAuthenticated(),
    user: req.isAuthenticated() ? {
      oid: req.user.oid,
      email: req.user.email || 'Email not available',
      displayName: req.user.displayName || 'N/A'
    } : null
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).send('An error occurred: ' + err.message);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});