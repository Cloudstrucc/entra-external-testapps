require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;

const app = express();
const port = process.env.PORT || 3000;

// Configure session middleware
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

// Configure passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Configure OIDC strategy
passport.use(new OIDCStrategy({
  identityMetadata: `https://login.microsoftonline.com/${process.env.TENANT_ID}/v2.0/.well-known/openid-configuration`,
  clientID: process.env.CLIENT_ID,
  responseType: 'code id_token',
  responseMode: 'form_post',
  redirectUrl: process.env.REDIRECT_URI,
  allowHttpForRedirectUrl: true,
  clientSecret: process.env.CLIENT_SECRET,
  validateIssuer: false,
  passReqToCallback: false,
  scope: ['profile', 'email', 'openid']
}, (iss, sub, profile, accessToken, refreshToken, done) => {
  return done(null, profile);
}));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Define routes
app.get('/', (req, res) => {
  res.send(req.isAuthenticated() ? `Welcome, ${req.user.displayName}! <a href="/logout">Logout</a>` : '<a href="/login">Login</a>');
});

app.get('/login', passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }));

app.post('/auth/openid/return',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/');
  }
);

app.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});