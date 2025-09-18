import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { v4 as uuid } from 'uuid';
import session from 'express-session';
import filestore from 'session-file-store';
import flash from 'express-flash';
import crypto from 'crypto';
import qs from "qs";
export class AuthUser {
    constructor(user) {
        this.authenticated = false;
        this.authenticate = (password) => {
            var digest = crypto.createHash('sha256').update(password.toString()).digest('hex');
            if (!this.password) {
                if (this.verbose) {
                    console.debug("no password");
                }
                return true;
            }
            else if (digest == this.password.toString()) {
                if (this.verbose) {
                    console.debug("password ok");
                }
                return true;
            }
            else {
                if (this.verbose) {
                    console.debug("password incorrect");
                }
                return false;
            }
        };
        this.username = user.name;
        this.password = user.password;
        this.role = user.role;
        this.id = user.id;
        this.token = user.token;
        this.verbose = user.verbose;
    }
}
export function tokenExtractor(req) {
    if (req && req.headers && req.headers.authorization) {
        return req.headers.authorization.replace(/^Bearer\s/, "");
    }
    //~ console.log({headers:req.headers,cookies:req.cookies,token:token})
    return null;
}
export default class Authentication {
    constructor(app, config, pool) {
        this.authenticate = (user, password) => {
            var digest = crypto.createHash('sha256').update(password.toString()).digest('hex');
            if (digest == user.password.toString()) {
                if (this.config.verbose) {
                    console.debug("password ok");
                }
                return true;
            }
            else {
                if (this.config.verbose) {
                    console.debug("password incorrect");
                }
                return false;
            }
        };
        this.loginReject = (req, mensaje, done) => {
            if (this.config.verbose) {
                console.debug("rejecting login");
            }
            if (req.headers['content-type'] == "application/x-www-form-urlencoded" || req.headers['content-type'] == "multipart/form-data") {
                var path = (req.body.path) ? req.body.path : "";
                //~ console.log("redirecting to " + path)
                req.res?.redirect(this.redirect_url + "?unauthorized=true&message=" + mensaje + "&path=" + path);
            }
            else {
                req.res?.status(401).send({ message: mensaje });
            }
            return done(null, false, { message: "Incorrect login" });
        };
        this.validateToken = async (token) => {
            const user = await this.findByJWT(token);
            if (!user) {
                if (this.config.verbose) {
                    console.error("User not found by token");
                }
                return;
            }
            else {
                if (this.config.verbose) {
                    console.debug("Found username:" + user.username);
                }
                user.authenticated = true;
                return user;
            }
        };
        this.extractAndValidateToken = async (req, verbose) => {
            var token = tokenExtractor(req);
            if (verbose) {
                console.debug("extractAndValidateToken: token:" + token);
            }
            if (!token) {
                return;
            }
            return this.validateToken(token)
                .then(user => {
                return user;
            });
        };
        this.loadOne = async (username) => {
            const result = await this.pool.query("SELECT id,name, role, encode(pass_enc,'escape') AS password, encode(token,'escape') AS token FROM users WHERE name=$1", [username]);
            if (!result) {
                return;
            }
            if (result.rows.length == 0) {
                return;
            }
            else {
                return new AuthUser({ ...result.rows[0], verbose: this.config.verbose });
            }
            // .catch(e=>{
            // 	console.error(e)
            // 	return
            // })
        };
        this.findById = async (id) => {
            const result = await this.pool.query("SELECT id, name, role, encode(pass_enc,'escape') AS password, encode(token,'escape') AS token FROM users WHERE id=$1", [id]);
            if (!result) {
                console.error("findById: user query failed");
                return;
            }
            if (result.rows.length == 0) {
                console.error("findById: user query returned 0 rows");
                return;
            }
            else {
                // console.log("findById: user query returned user " + result.rows[0].name)
                return new AuthUser({ ...result.rows[0], verbose: this.config.verbose });
            }
        };
        this.findByJWT = async (token) => {
            var digest = crypto.createHash('sha256').update(token.toString()).digest('hex');
            const result = await this.pool.query("SELECT id,name, role, user username, role, encode(pass_enc,'escape') AS password, encode(token,'escape') AS token from users where encode(token,'escape')=$1", [digest]);
            if (!result) {
                return;
            }
            if (result.rows.length == 0) {
                return;
            }
            else {
                return new AuthUser({ ...result.rows[0], verbose: this.config.verbose });
            }
        };
        this.isAuthenticated = async (req, res, next) => {
            if (this.config.rest.skip_authentication) {
                return next();
            }
            try {
                var user = await this.extractAndValidateToken(req); // try authentication by token (overrides session)
            }
            catch (e) {
                console.error(e);
                res.status(500).send("Internal Server Error");
                return;
            }
            if (user) {
                req.user = user;
                if (this.config.verbose) {
                    console.debug("isAuthenticated:" + JSON.stringify(req.user));
                }
            }
            logRequest(req);
            if (!req.user) {
                res.status(401).send("Unauthorized");
                return;
            }
            if (!req.user.authenticated) {
                res.status(401).send("Unauthorized");
                return;
            }
            return next();
        };
        this.isPublic = async (req, res, next) => {
            if (this.config.rest.skip_authentication) {
                return next();
            }
            if (this.config.rest.restricted) {
                if (req.user && req.user.role == "public") {
                    if (req.query) {
                        req.query.public = 'true';
                    }
                    else {
                        req.query = { public: 'true' };
                    }
                }
                return this.isAuthenticated(req, res, next);
            }
            if (this.config.verbose) {
                console.debug("isPublic: req.user (before check):" + JSON.stringify(req.user));
            }
            var user;
            if (!req.user) {
                try {
                    var user = await this.extractAndValidateToken(req); // try authentication by token (overrides session)
                }
                catch (e) {
                    console.error(e);
                    res.status(500).send("Internal Server Error");
                    return;
                }
            }
            if (user) {
                req.user = user;
                if (this.config.verbose) {
                    console.debug("isPublic req.user:" + JSON.stringify(req.user));
                }
            }
            if (!req.user || req.user.role == "public") {
                if (req.query) {
                    req.query.public = 'true';
                }
                else {
                    req.query = { public: 'true' };
                }
            }
            else if (!req.user.authenticated) {
                if (req.query) {
                    req.query.public = 'true';
                }
                else {
                    req.query = { public: 'true' };
                }
            }
            if (this.config.verbose) {
                console.debug("isPublic req.query:" + JSON.stringify(req.query));
            }
            logRequest(req);
            return next();
        };
        this.isAuthenticatedView = async (req, res, next) => {
            if (this.config.verbose) {
                console.debug("isAuthenticatedView");
            }
            if (this.config.rest.skip_authentication) {
                if (this.config.verbose) {
                    console.debug("Skip authentication");
                }
                return next();
            }
            //~ console.log(req)
            var path = (req.route) ? (req.route.path) ? req.route.path.replace(/^\//, "") : this.config.rest.index : this.config.rest.index;
            //~ var path = (req.originalUrl) ? req.originalUrl.replace(/^\//,"") : "secciones";
            if (req.query) {
                //~ console.log("adding query string")
                path += "&" + qs.stringify(req.query);
            }
            else {
                //~ console.log("no query string")
            }
            try {
                var user = await this.extractAndValidateToken(req); // try authentication by token (overrides session)
            }
            catch (e) {
                console.error(e);
                res.status(500).send("Internal Server Error");
                return;
            }
            if (user) {
                req.user = user;
                if (this.config.verbose) {
                    console.debug("isAuthenticatedView:" + JSON.stringify(user));
                }
            }
            if (!req.user) {
                res.redirect(this.redirect_url + '?redirected=true&path=' + path);
                return;
            }
            if (!req.user.authenticated) {
                res.redirect(this.redirect_url + '?redirected=true&path=' + path);
                return;
            }
            else if (req.user.role != "writer" && req.user.role != "admin") {
                req.query.writer = 'false';
                req.query.authenticated = 'true';
            }
            else {
                req.query.writer = 'true';
                req.query.authenticated = 'true';
            }
            logRequest(req);
            return next();
        };
        this.isPublicView = async (req, res, next) => {
            if (this.config.rest.skip_authentication) {
                req.query.writer = 'true';
                return next();
            }
            if (this.config.rest.restricted) {
                return this.isAuthenticatedView(req, res, next);
            }
            if (!req.query) {
                req.query = {};
            }
            try {
                var user = await this.extractAndValidateToken(req); // try authentication by token (overrides session)
            }
            catch (e) {
                console.error(e);
                res.status(500).send("Internal Server Error");
                return;
            }
            if (user) {
                req.user = user;
                if (this.config.verbose) {
                    console.debug("isPublicView:" + JSON.stringify(user));
                }
            }
            if (!req.user) {
                req.query.public = 'true';
                req.query.writer = 'false';
                req.query.authenticated = 'false';
            }
            else if (!req.user.authenticated) {
                req.query.public = 'true';
                req.query.writer = 'false';
                req.query.authenticated = 'false';
            }
            else if (req.user.role != "writer" && req.user.role != "admin") {
                req.query.writer = 'false';
                req.query.authenticated = 'true';
            }
            else {
                req.query.writer = 'true';
                req.query.authenticated = 'true';
            }
            logRequest(req);
            return next();
        };
        this.isWriter = async (req, res, next) => {
            if (this.config.rest.skip_authentication) {
                return next();
            }
            try {
                var user = await this.extractAndValidateToken(req); // try authentication by token (overrides session)
            }
            catch (e) {
                console.error(e);
                res.status(500).send("Internal Server Error");
                return;
            }
            if (user) {
                req.user = user;
                if (this.config.verbose) {
                    console.log("isWriter:" + JSON.stringify(user));
                }
            }
            logRequest(req);
            if (!req.user) {
                if (this.config.verbose) {
                    console.log("user not logged in");
                }
                res.status(401).send("Unauthorized");
                return;
            }
            if (!req.user.authenticated) {
                if (this.config.verbose) {
                    console.log("user not authenticated");
                }
                res.status(401).send("Unauthorized");
                return;
            }
            if (req.user.role != "writer" && req.user.role != "admin") {
                if (this.config.verbose) {
                    console.log("unathorized role");
                }
                res.status(401).send("Unauthorized");
                return;
            }
            return next();
        };
        this.isWriterView = async (req, res, next) => {
            var path = (req.route) ? (req.route.path) ? req.route.path.replace(/^\//, "") : "secciones" : "secciones";
            var query_string = "";
            //~ if(req.query && req.query.class) {
            //~ querystring += "&class=" + req.query.class
            //~ }
            if (req.query) {
                if (this.config.verbose) {
                    console.log("adding query string");
                }
                query_string += "&" + qs.stringify(req.query);
            }
            else {
                if (this.config.verbose) {
                    console.log("no query string");
                }
            }
            if (this.config.rest.skip_authentication) {
                return next();
            }
            try {
                var user = await this.extractAndValidateToken(req); // try authentication by token (overrides session)
            }
            catch (e) {
                console.error(e);
                res.status(500).send("Internal Server Error");
                return;
            }
            if (user) {
                req.user = user;
                if (this.config.verbose) {
                    console.log("isWriterView:" + JSON.stringify(user));
                }
            }
            logRequest(req);
            if (!req.user) {
                res.redirect(this.redirect_url + '?redirected=true&path=' + path + query_string);
                return;
            }
            if (!req.user.authenticated) {
                res.redirect(this.redirect_url + '?redirected=true&path=' + path + query_string);
                return;
            }
            if (req.user.role != "writer" && req.user.role != "admin") {
                if (this.config.verbose) {
                    console.log("unathorized role");
                }
                res.redirect(this.redirect_url + '?redirected=true&path=' + path + "&unauthorized=true" + query_string);
                return;
            }
            return next();
        };
        this.isAdmin = async (req, res, next) => {
            if (this.config.rest.skip_authentication) {
                return next();
            }
            if (this.config.verbose) {
                console.log({ user: req.user });
            }
            try {
                var user = await this.extractAndValidateToken(req); // try authentication by token (overrides session)
            }
            catch (e) {
                console.error(e);
                res.status(500).send("Internal Server Error");
                return;
            }
            if (user) {
                req.user = user;
                if (this.config.verbose) {
                    console.log("isAdmin:" + JSON.stringify(user));
                }
            }
            logRequest(req);
            if (!req.user) {
                if (this.config.verbose) {
                    console.log("user not logged in");
                }
                res.status(401).send("Unauthorized");
                return;
            }
            if (!req.user.authenticated) {
                if (this.config.verbose) {
                    console.log("user not authenticated");
                }
                res.status(401).send("Unauthorized");
                return;
            }
            if (req.user.role != "admin") {
                if (this.config.verbose) {
                    console.log("unathorized role");
                }
                res.status(401).send("Unauthorized");
                return;
            }
            return next();
        };
        this.isAdminView = async (req, res, next) => {
            var path = (req.route) ? (req.route.path) ? req.route.path.replace(/^\//, "") : "" : "";
            var query_string = "";
            if (req.query) {
                if (this.config.verbose) {
                    console.log("adding query string");
                }
                query_string += "&" + qs.stringify(req.query);
            }
            else {
                if (this.config.verbose) {
                    console.log("no query string");
                }
            }
            if (this.config.rest.skip_authentication) {
                return next();
            }
            if (this.config.verbose) {
                console.log({ user: req.user });
            }
            try {
                var user = await this.extractAndValidateToken(req); // try authentication by token (overrides session)
            }
            catch (e) {
                console.error(e);
                res.status(500).send("Internal Server Error");
                return;
            }
            if (user) {
                req.user = user;
                if (this.config.verbose) {
                    console.log("isAdminView:" + JSON.stringify(user));
                }
            }
            logRequest(req);
            if (!req.user) {
                res.redirect(this.redirect_url + '?redirected=true&path=' + path + query_string);
                return;
            }
            if (!req.user.authenticated) {
                res.redirect(this.redirect_url + '?redirected=true&path=' + path + query_string);
                return;
            }
            if (req.user.role != "admin") {
                if (this.config.verbose) {
                    console.log("unathorized role");
                }
                res.redirect(this.redirect_url + '?redirected=true&path=' + path + "&unauthorized=true" + query_string);
                return;
            }
            return next();
        };
        this.app = app;
        this.config = config;
        this.pool = pool;
        this.redirect_url = (this.config.rest.redirect_url) ? this.config.rest.redirect_url : "login";
        this.FileStore = filestore(session);
        this.app.set('trust proxy', 1);
        this.app.use(session({
            cookie: {
                maxAge: (this.config.rest.cookieMaxAge) ? this.config.rest.cookieMaxAge : 3 * 60 * 60 * 1000,
                secure: (this.config.rest.secure) ? true : false,
                sameSite: 'lax'
            },
            secret: 'secret',
            // key: "id",
            genid: (req) => {
                if (this.config.verbose) {
                    console.debug('Inside session middleware genid function');
                    console.debug(`Request object sessionID from client: ${req.sessionID}`);
                }
                if (req.sessionID) {
                    return req.sessionID;
                }
                else {
                    return uuid(); // use UUIDs for session IDs
                }
            },
            store: new this.FileStore({ logFn: function () { }, path: config.rest.session_file_store || "sessions" }),
            resave: false,
            saveUninitialized: false,
            rolling: true
        }));
        this.app.use(passport.initialize());
        this.app.use(passport.session());
        this.app.use(flash());
        // configure passport.js to use the local strategy
        passport.use(new LocalStrategy({
            passReqToCallback: true,
            usernameField: 'username',
            passwordField: 'password'
        }, (req, username, password, done) => {
            if (this.config.verbose) {
                console.debug("login attempt at " +
                    new Date().toISOString());
            }
            this.loadOne(username)
                .then(user => {
                if (!user) { // User.authenticate(user,password)) {
                    req.flash('error', 'Usuario no encontrado');
                    if (this.config.verbose) {
                        console.debug("LocalStrategy: usuario no encontrado");
                    }
                    return this.loginReject(req, 'Usuario no encontrado', done);
                }
                else {
                    if (this.config.verbose) {
                        console.debug("LocalStrategy: got user: " + user.username + " at " + new Date().toISOString());
                    }
                    if (!user.authenticate(password)) { // User
                        if (this.config.verbose) {
                            console.debug("LocalStrategy: Password incorrecto");
                        }
                        return this.loginReject(req, 'Password incorrecto', done);
                    }
                }
                if (this.config.verbose) {
                    console.debug("LocalStrategy: Correct login");
                }
                done(null, user);
            })
                .catch(e => {
                console.log(e);
                done(e, false);
            });
        }));
        passport.serializeUser(function (user, done) {
            done(null, user.id);
        });
        passport.deserializeUser(async (id, done) => {
            // console.debug("deserializing user with id: " + id)
            try {
                var user = await this.findById(id);
            }
            catch (e) {
                done(e, null);
            }
            //~ console.log({user:user})
            if (user) {
                user.authenticated = true;
                done(null, user);
            }
            else {
                console.error("User not found");
                done(null, null);
                // done(new Error("user not found"),null)
            }
        });
        // my custom middleware
        this.passport = passport;
    }
}
function logRequest(req) {
    var username, authenticated, role;
    if (req.user && req.user.username) {
        username = req.user.username;
        authenticated = true;
        role = req.user.role;
    }
    else {
        username = "anonymous";
        authenticated = false;
        role = "none";
    }
    console.log(req.protocol + " " + req.method + " " + req.originalUrl + " " + username + ":" + authenticated + ":" + role + " " + req.socket.bytesRead);
    return;
}
