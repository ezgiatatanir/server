passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
},
function(accessToken, refreshToken, profile, done) {
  const query = 'SELECT * FROM google_users WHERE google_id = ?';
  db.query(query, [profile.id], (err, results) => {
    if (err) return done(err);

    if (results.length > 0) {
      // Kullanıcı veritabanında var, kullanıcı bilgilerini güncelle
      const updateQuery = 'UPDATE google_users SET display_name = ?, email = ? WHERE google_id = ?';
      db.query(updateQuery, [profile.displayName, profile.emails[0].value, profile.id], (err) => {
        if (err) return done(err);
        return done(null, profile);
      });
    } else {
      // Kullanıcı veritabanında yok, yeni kullanıcı oluştur
      const insertQuery = 'INSERT INTO google_users (google_id, display_name, email) VALUES (?, ?, ?)';
      db.query(insertQuery, [profile.id, profile.displayName, profile.emails[0].value], (err) => {
        if (err) return done(err);
        return done(null, profile);
      });
    }
  });
}
));
