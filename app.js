require('dotenv').config();
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const app = express();
app.use(express.json());  // This line is crucial for parsing JSON bodies sent through fetch

// EJS View Engine ve Views Klasörü Ayarı
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// MySQL bağlantısı
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '123456',
  database: 'uygulama'
});

// MySQL bağlantısını aç
db.connect((err) => {
  if (err) {
    console.error('MySQL bağlantısı başarısız: ' + err.message);
    return;
  }
  console.log('MySQL bağlantısı başarıyla kuruldu');
});

// Express middleware'leri
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
},
function(accessToken, refreshToken, profile, done) {
  const googleId = profile.id;
  
  const query = 'SELECT * FROM users WHERE google_id = ?';
  db.query(query, [googleId], (err, results) => {
    if (err) return done(err);

    if (results.length > 0) {
      // Kullanıcı veritabanında var, kullanıcı bilgilerini güncelle
      const updateQuery = 'UPDATE users SET firstName = ?, email = ? WHERE google_id = ?';
      db.query(updateQuery, [profile.displayName, profile.emails[0].value, googleId], (err) => {
        if (err) return done(err);
        const user = { id: results[0].id, firstName: profile.displayName, email: profile.emails[0].value };
        return done(null, user);
      });
    } else {
      // Kullanıcı veritabanında yok, yeni kullanıcı oluştur
      const insertQuery = 'INSERT INTO users (google_id, firstName, email) VALUES (?, ?, ?)';
      db.query(insertQuery, [googleId, profile.displayName, profile.emails[0].value], (err, result) => {
        if (err) return done(err);
        const newUser = { id: result.insertId, google_id: googleId, firstName: profile.displayName, email: profile.emails[0].value };
        return done(null, newUser);
      });
    }
  });
}
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  const query = 'SELECT * FROM users WHERE id = ?';
  db.query(query, [id], (err, results) => {
    if (err || results.length === 0) return done(err || new Error("User not found"));
    const user = { id: results[0].id, firstName: results[0].firstName, email: results[0].email };
    done(null, user);
  });
});

// Google OAuth 2.0 kimlik doğrulama rotaları
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Kullanıcı başarılı bir şekilde giriş yaptıktan sonra oturum bilgilerini sakla
    req.session.user = { id: req.user.id, name: req.user.firstName };
    res.redirect('/home');  // Giriş başarılı, anasayfaya yönlendir
  }
);


// Login Route
app.get('/login', (req, res) => {
  res.render('login_page');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { firstName, lastName, email, password, country, city } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (firstName, lastName, email, password, country, city) 
                   VALUES (?, ?, ?, ?, ?, ?)`;
    db.query(query, [firstName, lastName, email, hashedPassword, country, city], (err, result) => {
      if (err) {
        res.status(500).send('Registration failed: ' + err.message);
      } else {
        res.redirect('/home');  // Başarılı kayıt sonrası anasayfaya yönlendirme
      }
    });
  } catch (error) {
    res.status(500).send("Server Error: " + error.message);
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err || results.length === 0 || !(await bcrypt.compare(password, results[0].password))) {
      res.status(401).send('Login failed');
    } else {
      req.session.user = { id: results[0].id, name: results[0].firstName };
      res.redirect('/home');  // Giriş başarılı, anasayfaya yönlendir
    }
  });
});

app.get('/home', (req, res) => {
  if (req.session.user) {
    // Veritabanından film verilerini çek
    const movieQuery = 'SELECT * FROM films LIMIT 10';
    db.query(movieQuery, (err, movies) => {
      if (err) {
        res.status(500).send('Veritabanı hatası: ' + err.message);
      } else {
        // Filmleri ve kullanıcı bilgilerini şablona gönder
        res.render('home_page', { user: req.session.user, movies: movies });
      }
    });
  } else {
    res.redirect('/login');
  }
});

// Kök dizine yapılan isteklerde anasayfa'yı sun
app.get('/', (req, res) => {

  
  const movieQuery = 'SELECT * FROM films LIMIT 10';
  db.query(movieQuery, (err, movies) => {
    if (err) {
      res.status(500).send('Veritabanı hatası: ' + err.message);
    } else {
      // Filmleri ve kullanıcı bilgilerini şablona gönder
  if (req.session.user) {
    // If user is already logged in, render the home page with user details
    res.render('home_page', { user: req.session.user, movies: movies });
  } else {
    // Render the home page without user details, showing only 'Sign In'
    res.render('home_page', { user: null, movies: movies });
  }
}
  });
});

app.get('/search_results', (req, res) => {
  const query = req.query.q;
  const category = req.query.category;

  let sqlQuery = '';
  let sqlParams = [];

  if (category === 'movies') {
      sqlQuery = `
          SELECT id, title, description, release_date, director, genre, imdb_score, poster_url, trailer_url, 'film' AS type 
          FROM films 
          WHERE title LIKE ? 
          LIMIT 3`;
      sqlParams = [`%${query}%`];
  } else if (category === 'celebs') {
      sqlQuery = `
          SELECT id, name AS title, aka AS description, NULL AS release_date, NULL AS director, NULL AS genre, NULL AS imdb_score, profile_pic_url AS poster_url, NULL AS trailer_url, 'actor' AS type 
          FROM actors 
          WHERE name LIKE ? 
          LIMIT 3`;
      sqlParams = [`%${query}%`];
  } else { // All category
      sqlQuery = `
          SELECT id, title, description, release_date, director, genre, imdb_score, poster_url, trailer_url, 'film' AS type 
          FROM films 
          WHERE title LIKE ? 
          UNION 
          SELECT id, name AS title, aka AS description, NULL AS release_date, NULL AS director, NULL AS genre, NULL AS imdb_score, profile_pic_url AS poster_url, NULL AS trailer_url, 'actor' AS type 
          FROM actors 
          WHERE name LIKE ?
          LIMIT 3`;
      sqlParams = [`%${query}%`, `%${query}%`];
  }

  db.query(sqlQuery, sqlParams, (err, results) => {
      if (err) {
          return res.status(500).json({ error: err.message });
      }

      // Filmler için cast bilgilerini çek
      const filmResults = results.filter(result => result.type === 'film' || !result.type);
      const promises = filmResults.map(film => {
          return new Promise((resolve, reject) => {
              const castQuery = `
                  SELECT a.name, a.aka, a.profile_pic_url
                  FROM actors a
                  JOIN film_actors fa ON a.id = fa.actor_id
                  WHERE fa.film_id = ?`;
              db.query(castQuery, [film.id], (err, castResults) => {
                  if (err) {
                      reject(err);
                  } else {
                      film.cast = castResults;
                      resolve();
                  }
              });
          });
      });

      Promise.all(promises).then(() => {
          res.render('search_results', { results, query, category });
      }).catch(err => {
          res.status(500).json({ error: err.message });
      });
  });
});



app.get('/movie/:id', (req, res) => {
  const movieId = req.params.id;
  const movieQuery = `SELECT * FROM films WHERE id = ?`;
  const castQuery = `
    SELECT a.name, a.aka, a.profile_pic_url
    FROM actors a
    JOIN film_actors fa ON a.id = fa.actor_id
    WHERE fa.film_id = ?`;

  db.query(movieQuery, [movieId], (err, movieResults) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).send('Database query error');
    }
    if (movieResults.length === 0) {
      console.log('Movie not found:', movieId);
      return res.status(404).send('Movie not found');
    }
    const movie = movieResults[0];
    
    db.query(castQuery, [movieId], (err, castResults) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).send('Database query error');
      }
      res.render('movie_details', { movie, cast: castResults, user: req.session.user });
    });
  });
});

app.post('/rate_movie', async (req, res) => {
  if (!req.session.user) {
    res.status(401).send('Not authorized');
    return;
  }

  const { film_id, rating, comment } = req.body;
  const user_id = req.session.user.id;
  
  try {
    const insertQuery = 'INSERT INTO ratings (user_id, film_id, rating, comment) VALUES (?, ?, ?, ?)';
    db.query(insertQuery, [user_id, film_id, rating, comment], (err, result) => {
      if (err) {
        res.status(500).send('Error saving rating: ' + err.message);
        return;
      }
      res.send('Rating submitted successfully');
    });
  } catch (error) {
    res.status(500).send("Server Error: " + error.message);
  }
});
// Route to add a movie to the user's watchlist
// Assuming you have a table called 'watchlist' with at least 'user_id' and 'film_id' columns
// Route to add a movie to the watchlist
// Route to add a movie to the watchlist
// Route to add a movie to the watchlist
app.post('/add-to-watchlist', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'You must be logged in to add items to your watchlist.' });
  }

  const filmId = req.body.film_id;
  const userId = req.session.user.id;

  if (!filmId) {
    return res.status(400).json({ error: 'Film ID cannot be null' });
  }

  const query = `INSERT INTO watchlist (user_id, film_id) VALUES (?, ?)`;

  db.query(query, [userId, filmId], (err, result) => {
    if (err) {
      console.error('Failed to add to watchlist:', err);
      return res.status(500).json({ error: 'Failed to add to watchlist' });
    }
    res.json({ message: 'Movie added to watchlist successfully' });
  });
});





// Route to get the watchlist for the logged-in user
app.get('/watchlist', (req, res) => {
  if (!req.session.user) {
      return res.redirect('/login'); // Redirect to login if user is not logged in
  }

  const userId = req.session.user.id;
  const query = `
      SELECT f.id, f.title, f.description, f.poster_url 
      FROM films f
      JOIN watchlist w ON f.id = w.film_id
      WHERE w.user_id = ?;
  `;

  db.query(query, [userId], (err, watchlistMovies) => {
      if (err) {
          console.error('Database error:', err);
          return res.status(500).send('Database error');
      }
      // Check if watchlistMovies is undefined or null
      if (!watchlistMovies) {
          watchlistMovies = []; // Ensure the variable is always an array
      }
      res.render('watchlist_page', { user: req.session.user, watchlistMovies });
  });
});





app.get('/search', (req, res) => {
  const query = req.query.q;
  const category = req.query.category;

  let sqlQuery = '';
  let sqlParams = [];

  if (category === 'movies') {
      sqlQuery = `SELECT id, title, description, release_date, director, genre, imdb_score, poster_url, trailer_url FROM films WHERE title LIKE ? LIMIT 3`;
      sqlParams = [`%${query}%`];
  } else if (category === 'celebs') {
      sqlQuery = `SELECT id, name, aka, profile_pic_url FROM actors WHERE name LIKE ? LIMIT 3`;
      sqlParams = [`%${query}%`];
  } else { // All category
      sqlQuery = `
          SELECT id, title, description, release_date, director, genre, imdb_score, poster_url, trailer_url, 'film' AS type FROM films WHERE title LIKE ? 
          UNION 
          SELECT id, name AS title, aka AS description, NULL AS release_date, NULL AS director, NULL AS genre, NULL AS imdb_score, profile_pic_url AS poster_url, NULL AS trailer_url, 'actor' AS type FROM actors WHERE name LIKE ?
          LIMIT 3`;
      sqlParams = [`%${query}%`, `%${query}%`];
  }

  db.query(sqlQuery, sqlParams, (err, results) => {
      if (err) {
          return res.status(500).json({ error: err.message });
      }
      res.json(results);
  });
});



app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});
// 404 Hatası İçin Middleware
app.use((req, res, next) => {
  res.status(404).send("404 - Sayfa Bulunamadı");
});

// Sunucuyu dinle
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Sunucu ${PORT} portunda çalışıyor`);
});

