require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

const mongoUri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;

let userCollection;

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

// Session - registered before routes
app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: mongoUri,
    dbName: process.env.MONGODB_DATABASE,
    collectionName: 'sessions',
    crypto: { secret: process.env.MONGODB_SESSION_SECRET }
  }),
  cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// Home
app.get('/', (req, res) => {
  if (req.session.authenticated) {
    res.send(`
      <!DOCTYPE html><html><head><title>Home</title></head><body>
      <h1>Hello, ${req.session.name}!</h1>
      <a href="/members"><button>Go to Members Area</button></a><br><br>
      <a href="/logout"><button>Logout</button></a>
      </body></html>
    `);
  } else {
    res.send(`
      <!DOCTYPE html><html><head><title>Home</title></head><body>
      <h1>Welcome</h1>
      <a href="/signup"><button>Sign up</button></a><br><br>
      <a href="/login"><button>Log in</button></a>
      </body></html>
    `);
  }
});

// Sign up - GET
app.get('/signup', (req, res) => {
  res.send(`
    <!DOCTYPE html><html><head><title>Sign Up</title></head><body>
    <h2>create user</h2>
    <form action="/signupSubmit" method="POST">
      <input name="name" placeholder="name"><br>
      <input name="email" placeholder="email"><br>
      <input name="password" type="password" placeholder="password"><br>
      <button type="submit">Submit</button>
    </form>
    </body></html>
  `);
});

// Sign up - POST
app.post('/signupSubmit', async (req, res) => {
  const { name, email, password } = req.body;

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required()
  });

  const { error } = schema.validate({ name, email, password });
  if (error) {
    const msg = error.details[0].message;
    let friendly = 'Please fill in all fields.';
    if (msg.includes('"name"')) friendly = 'Name is required.';
    else if (msg.includes('"email"')) friendly = 'Please provide an email address.';
    else if (msg.includes('"password"')) friendly = 'Password is required.';
    return res.send(`
      <!DOCTYPE html><html><head><title>Error</title></head><body>
      <p>${friendly}</p>
      <a href="/signup">Try again</a>
      </body></html>
    `);
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;

  req.session.save((err) => {
    if (err) console.error('Session save error:', err);
    res.redirect('/members');
  });
});

// Log in - GET
app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html><html><head><title>Log In</title></head><body>
    <h2>log in</h2>
    <form action="/loginSubmit" method="POST">
      <input name="email" placeholder="email"><br>
      <input name="password" type="password" placeholder="password"><br>
      <button type="submit">Submit</button>
    </form>
    </body></html>
  `);
});

// Log in - POST
app.post('/loginSubmit', async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required()
  });

  const { error } = schema.validate({ email, password });
  if (error) {
    return res.send(`
      <!DOCTYPE html><html><head><title>Error</title></head><body>
      <p>Invalid email/password combination.</p>
      <a href="/login">Try again</a>
      </body></html>
    `);
  }

  const user = await userCollection.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.send(`
      <!DOCTYPE html><html><head><title>Error</title></head><body>
      <p>Invalid email/password combination.</p>
      <a href="/login">Try again</a>
      </body></html>
    `);
  }

  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = user.email;

  req.session.save((err) => {
    if (err) console.error('Session save error:', err);
    res.redirect('/members');
  });
});

// Members - GET
app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/');
  }

  const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <!DOCTYPE html><html><head><title>Members</title></head><body>
    <h1>Hello, ${req.session.name}.</h1>
    <img src="/${randomImage}" style="max-width:300px"><br><br>
    <a href="/logout"><button>Sign out</button></a>
    </body></html>
  `);
});

// Log out
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 404
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html><html><head><title>404</title></head><body>
    <h1>Page not found - 404</h1>
    </body></html>
  `);
});

// Start server only after DB connects
async function startServer() {
  const client = new MongoClient(mongoUri);
  await client.connect();
  const db = client.db(process.env.MONGODB_DATABASE);
  userCollection = db.collection('users');
  console.log('Connected to MongoDB');
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

startServer().catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});