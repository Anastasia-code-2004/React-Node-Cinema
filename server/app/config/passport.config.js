// app/config/passport.config.js

const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const db = require('../models');
const User = db.users; // Убедитесь, что путь к модели правильный

module.exports = (passport) => {
    // Локальная стратегия
    passport.use(new LocalStrategy(
        {
            usernameField: 'username', // указываем, какое поле будет использоваться для имени пользователя
            passwordField: 'password', // указываем, какое поле будет использоваться для пароля
        },
        async (username, password, done) => { // эта функция выполняется при запросе passport.authenticate('local')
            try {
                const user = await User.findOne({ username });
                if (!user) {
                    return done(null, false, { message: 'Incorrect username.' });
                }

                const isMatch = await user.verifyPassword(password);
                if (!isMatch) {
                    return done(null, false, { message: 'Incorrect password.' });
                }

                return done(null, user);
            } catch (err) {
                return done(err);
            }
        }
    ));

    // Google стратегия
    passport.use(new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
  	    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: process.env.GOOGLE_CALLBACK_URL,
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                // Поиск пользователя по Google ID
                let user = await User.findOne({ googleId: profile.id });

                // Если пользователя нет, создаем его
                if (!user) {
                    user = new User({
                        googleId: profile.id,
                        username: profile.displayName,
                        email: profile.emails[0].value
                    });
                    await user.save();
                }

                return done(null, user);
            } catch (err) {
                return done(err);
            }
        }
    ));

    // Facebook стратегия
    passport.use(new FacebookStrategy(
        {
            clientID: process.env.FACEBOOK_APP_ID,
            clientSecret: process.env.FACEBOOK_APP_SECRET,
            callbackURL: process.env.FACEBOOK_CALLBACK_URL,
            profileFields: ['id', 'displayName', 'emails'] // Задайте поля, которые хотите получить от Facebook
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                // Поиск пользователя по Facebook ID
                let user = await User.findOne({ facebookId: profile.id });

                // Если пользователя нет, создаем его
                if (!user) {
                    user = new User({
                        facebookId: profile.id,
                        username: profile.displayName,
                        email: profile.emails[0].value
                    });
                    await user.save();
                }

                return done(null, user);
            } catch (err) {
                return done(err);
            }
        }
    ));

    // Сериализация пользователя
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            done(null, user);
        } catch (err) {
            done(err, null);
        }
    });
};