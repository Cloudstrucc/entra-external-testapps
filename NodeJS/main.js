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

// Middleware to log all requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Configure passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, { oid: user.oid, email: user.email });
});

passport.deserializeUser((user, done) => {
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

// Configure OIDC strategy
passport.use(new OIDCStrategy({
  identityMetadata: `https://cloudstruccentradev.ciamlogin.com/${process.env.TENANT_ID}/v2.0/.well-known/openid-configuration`,
  clientID: process.env.CLIENT_ID,
  responseType: 'id_token',
  responseMode: 'form_post',
  redirectUrl: process.env.REDIRECT_URI,
  allowHttpForRedirectUrl: true,
  clientSecret: process.env.CLIENT_SECRET,
  validateIssuer: false,
  passReqToCallback: true,
  scope: ['openid', 'profile', 'email'],
  loggingLevel: 'info',
  loggingNoPII: false
}, (req, iss, sub, profile, accessToken, refreshToken, params, done) => {
  console.log('OIDC Strategy Callback:');
  console.log('Issuer:', iss);
  console.log('Subject:', sub);
  console.log('Profile:', JSON.stringify(profile, null, 2));
  console.log('Access Token:', accessToken ? prettyPrintJwt(accessToken) : 'Not present');
  
  // Extract id_token from profile._raw if params is null
  let idToken = params && params.id_token ? params.id_token : null;
  if (!idToken && profile._raw) {
    try {
      const rawProfile = JSON.parse(profile._raw);
      idToken = rawProfile.id_token;
    } catch (error) {
      console.error('Error parsing profile._raw:', error);
    }
  }
  
  console.log('ID Token:', idToken ? prettyPrintJwt(idToken) : 'Not present');
  console.log('Refresh Token:', refreshToken ? 'Present' : 'Not present');
  
  if (!profile.oid) {
    return done(new Error("No OID found"), null);
  }
  
  // Save the id_token and email to the profile for later use
  profile.id_token = idToken;
  profile.email = profile._json.email || profile._json.preferred_username;
  
  return done(null, profile);
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

app.post('/auth/openid/return', (req, res, next) => {
  console.log('Auth return route accessed');
  console.log('Request body:', req.body);
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

app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).send('Unauthorized: No user logged in');
  }
  
  res.json({
    message: `Welcome, ${req.user.displayName || req.user.email || 'User'}!`,
    profile: {
      oid: req.user.oid,
      email: req.user.email,
      displayName: req.user.displayName || 'N/A'
    }
  });
});

// Debug route to display the raw token
app.get('/debug/token', (req, res) => {
  if (!req.isAuthenticated() || !req.user.id_token) {
    return res.status(401).send('No token available');
  }
  res.send(`<pre>${prettyPrintJwt(req.user.id_token)}</pre>`);
});

// Route to check current authentication status
app.get('/status', (req, res) => {
  res.json({
    authenticated: req.isAuthenticated(),
    user: req.isAuthenticated() ? {
      oid: req.user.oid,
      email: req.user.email,
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