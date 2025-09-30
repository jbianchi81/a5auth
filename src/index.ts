import type { Express, Request, Response } from 'express'; 
import { Pool } from 'pg'
import passport from 'passport'
import { Strategy as LocalStrategy } from 'passport-local';
import {v4 as uuid} from 'uuid'
import session from 'express-session'
import filestore from 'session-file-store';
import flash from 'express-flash'
import crypto from 'crypto'
import qs from "qs";

export {User} from './userAdmin'

export interface AuthenticationConfig {
	rest: {
		index: any;
		restricted: any;
		cookieMaxAge: any;
		redirect_url?: string, 
		secure?: boolean,
		session_file_store?: string,
		skip_authentication?: boolean
	},
	verbose?: boolean
}

export class AuthUser {

	username : string
	password: string
	role : string
	id : string
	token : string
	verbose?: boolean | undefined
	authenticated: boolean = false
	
	constructor (user : {name : string, password: string, role : string, id : string, token : string, verbose?: boolean}) {
		this.username = user.name
		this.password = user.password
		this.role = user.role
		this.id = user.id
		this.token = user.token
		this.verbose = user.verbose
	}

	authenticate = (password : string) => {
		var digest = crypto.createHash('sha256').update(password.toString()).digest('hex')
		if(!this.password) {
			if(this.verbose) {
				console.debug("no password")
			}
			return true
		} else if( digest == this.password.toString()) {
			if(this.verbose) {
				console.debug("password ok")
			}
			return true
		} else {
			if(this.verbose) {
				console.debug("password incorrect")
			}
			return false
		}
	}
}

export function tokenExtractor(req : Request) : string | null {
	if (req && req.headers && req.headers.authorization) {
		return req.headers.authorization.replace(/^Bearer\s/,"");
	}
	//~ console.log({headers:req.headers,cookies:req.cookies,token:token})
	return null;
}

export default class Authentication {   // needs: app.use(express.urlencoded())
	app : Express
	config : AuthenticationConfig
	pool : Pool
	redirect_url : string
	FileStore : filestore.FileStore
	passport : passport.PassportStatic
	
	constructor(app : Express,config : AuthenticationConfig, pool : Pool)  {
		this.app = app
		this.config = config
		this.pool = pool
		this.redirect_url = (this.config.rest.redirect_url) ? this.config.rest.redirect_url : "login"
		this.FileStore = filestore(session);

		this.app.set('trust proxy',1)

		this.app.use(session({
			cookie: {
				maxAge: (this.config.rest.cookieMaxAge) ? this.config.rest.cookieMaxAge : 3 * 60 * 60 * 1000,
				secure: (this.config.rest.secure) ? true : false,
				sameSite: 'lax'
			}, 
			secret: 'secret', 
			// key: "id",
			genid: (req) => {
				if(this.config.verbose) {
					console.debug('Inside session middleware genid function')
					console.debug(`Request object sessionID from client: ${req.sessionID}`)
				}
				if(req.sessionID) {
					return req.sessionID
				} else {
					return uuid() // use UUIDs for session IDs
				}
			},
			store: new this.FileStore({logFn: function(){},path: config.rest.session_file_store || "sessions"}),
			resave: false,
			saveUninitialized: false,
			rolling: true
		}));
		this.app.use(passport.initialize());
		this.app.use(passport.session());
		this.app.use(flash());

		// configure passport.js to use the local strategy
		passport.use(new LocalStrategy( 
			{ 
				passReqToCallback: true, 
				usernameField: 'username', 
				passwordField: 'password' 
			}, 
			(req, username, password, done) => {      //{usernameField: 'username', passwordField: 'password'},
				if(this.config.verbose) {
					console.debug("login attempt at " + 
					new Date().toISOString())
				}
				this.loadOne(username)
				.then(user=>{
					if(!user) { // User.authenticate(user,password)) {
						req.flash('error', 'Usuario no encontrado')
						if(this.config.verbose) {
							console.debug("LocalStrategy: usuario no encontrado")
						}
						return this.loginReject(req,'Usuario no encontrado',done)
					}
					else {
						if(this.config.verbose) {
							console.debug("LocalStrategy: got user: " + user.username + " at " + new Date().toISOString())
						}
						if (!user.authenticate(password)) { // User
							if(this.config.verbose) {
								console.debug("LocalStrategy: Password incorrecto")
							}
							return this.loginReject(req,'Password incorrecto',done)
						}
					}
					if(this.config.verbose) {
						console.debug("LocalStrategy: Correct login")
					}
					done(null,user)
				})
				.catch(e=>{
					console.log(e)
					done(e,false)
				})
		}))

		passport.serializeUser(function(user, done) {
			done(null, (user as any).id);
		});
		passport.deserializeUser(async (id : number, done) => {
			// console.debug("deserializing user with id: " + id)
			try {
				var user = await this.findById(id)
			} catch (e) {
				done(e,null)
			}
			//~ console.log({user:user})
			if(user) {
				user.authenticated = true
				done(null, user);
			} else {
				console.error("User not found")
				done(null,null)
				// done(new Error("user not found"),null)
			}
		}); 

		// my custom middleware

		this.passport = passport

	}

	
	authenticate = (user : AuthUser, password : string) : boolean => {
		var digest = crypto.createHash('sha256').update(password.toString()).digest('hex')
		if( digest == user.password.toString()) {
			if(this.config.verbose) {
				console.debug("password ok")
			}
			return true
		} else {
			if(this.config.verbose) {
				console.debug("password incorrect")
			}
			return false
		}
	}

	loginReject = (req : Request,mensaje : string,done: (arg0: null, arg1: boolean, arg2: { message: string; }) => any) => { 
		if(this.config.verbose) {
			console.debug("rejecting login")
		}
		if(req.headers['content-type'] == "application/x-www-form-urlencoded" || req.headers['content-type'] == "multipart/form-data") {
			var path = (req.body.path) ? req.body.path : ""
			//~ console.log("redirecting to " + path)
			req.res?.redirect(this.redirect_url + "?unauthorized=true&message="+mensaje+"&path="+path)
		} else {
			req.res?.status(401).send({message:mensaje})
		}
		return done(null,false, {message: "Incorrect login"})
	}


	validateToken = async (token : string) => {
		const user = await this.findByJWT(token)
		if(!user) {
			if(this.config.verbose) {
				console.error("User not found by token")
			}
			return
		} else {
			if(this.config.verbose) {
				console.debug("Found username:" + user.username)
			}
			user.authenticated = true
			return user
		}
	}

	extractAndValidateToken = async (req : Request, verbose?: boolean) => {
		var token = tokenExtractor(req)
		if(verbose) {
			console.debug("extractAndValidateToken: token:" + token)
		}
		if(!token) {
			return
		}
		return this.validateToken(token)
		.then(user=>{
			return user
		})
	}

	loadOne = async (username : string) => {
		const result = await this.pool.query("SELECT id,name, role, encode(pass_enc,'escape') AS password, encode(token,'escape') AS token FROM users WHERE name=$1", [username]);
		if (!result) {
			return;
		}
		if (result.rows.length == 0) {
			return;
		} else {
			return new AuthUser({...result.rows[0], verbose: this.config.verbose});
		}
		// .catch(e=>{
		// 	console.error(e)
		// 	return
		// })
	}
	findById = async (id : number) : Promise<AuthUser | undefined> => {
		const result = await this.pool.query("SELECT id, name, role, encode(pass_enc,'escape') AS password, encode(token,'escape') AS token FROM users WHERE id=$1", [id]);
		if (!result) {
			console.error("findById: user query failed");
			return;
		}
		if (result.rows.length == 0) {
			console.error("findById: user query returned 0 rows");
			return;
		} else {
			// console.log("findById: user query returned user " + result.rows[0].name)
			return new AuthUser({...result.rows[0], verbose: this.config.verbose});
		}
	}
	findByJWT = async (token : string) : Promise<AuthUser | undefined> => {
		var digest = crypto.createHash('sha256').update(token.toString()).digest('hex')
		const result = await this.pool.query("SELECT id,name, role, user username, role, encode(pass_enc,'escape') AS password, encode(token,'escape') AS token from users where encode(token,'escape')=$1", [digest]);
		if (!result) {
			return;
		}
		if (result.rows.length == 0) {
			return;
		} else {
			return new AuthUser({...result.rows[0], verbose: this.config.verbose});
		}	
	}	

	isAuthenticated = async (req : Request,res : Response,next: () => any) => {
		if(this.config.rest.skip_authentication) {
			return next()
		}
		try {
			var user = await this.extractAndValidateToken(req) // try authentication by token (overrides session)
		} catch (e) {
			console.error(e)
			res.status(500).send("Internal Server Error")
			return
		}
		if(user) {
			req.user = user
			if(this.config.verbose) {
				console.debug("isAuthenticated:" + JSON.stringify(req.user))
			}
		}
		logRequest(req)
		if(!req.user) {
			res.status(401).send("Unauthorized")
			return
		}
		if(!(req.user as any).authenticated) {
			res.status(401).send("Unauthorized")
			return
		}
		return next()
	}

	isPublic = async (req : Request,res : Response,next : () => any) => {
		if(this.config.rest.skip_authentication) {
			return next()
		}
		if(this.config.rest.restricted) {
			if(req.user && (req.user as any).role == "public") {
				if(req.query) {
					req.query.public = 'true'
				} else {
					req.query = {public:'true'}
				}
			}
			return this.isAuthenticated(req,res,next)
		}
		if(this.config.verbose) {
			console.debug("isPublic: req.user (before check):" + JSON.stringify(req.user))
		}
		var user : AuthUser | undefined
		if(!req.user) {
			try {
				var user = await this.extractAndValidateToken(req) // try authentication by token (overrides session)
			} catch (e) {
				console.error(e)
				res.status(500).send("Internal Server Error")
				return
			}
		}
		if(user) {
			req.user = user
			if(this.config.verbose) {
				console.debug("isPublic req.user:" + JSON.stringify(req.user))
			}
		}
		if(!req.user || (req.user as any).role == "public") {
			if(req.query) {
				req.query.public = 'true'
			} else {
				req.query = {public:'true'}
			}
		} else if (!(req.user as any).authenticated) {
			if(req.query) {
				req.query.public = 'true'
			} else {
				req.query = {public:'true'}
			}
		}
		if(this.config.verbose) {
			console.debug("isPublic req.query:" + JSON.stringify(req.query))
		}
		logRequest(req)
		return next()
	}

	isAuthenticatedView = async (req : Request,res : Response, next : () => any) => {
		if(this.config.verbose) {
			console.debug("isAuthenticatedView")
		}
		if(this.config.rest.skip_authentication) {
			if(this.config.verbose) {
				console.debug("Skip authentication")
			}
			return next()
		}
		//~ console.log(req)
		var path = (req.route) ? (req.route.path) ? req.route.path.replace(/^\//,"") : this.config.rest.index : this.config.rest.index ;
		//~ var path = (req.originalUrl) ? req.originalUrl.replace(/^\//,"") : "secciones";
		if(req.query) {
			//~ console.log("adding query string")
			path += "&" + qs.stringify(req.query)
		} else {
			//~ console.log("no query string")
		}
		try {
			var user = await this.extractAndValidateToken(req) // try authentication by token (overrides session)
		} catch (e) {
			console.error(e)
			res.status(500).send("Internal Server Error")
			return
		}
		if(user) {
			req.user = user
			if(this.config.verbose) {
				console.debug("isAuthenticatedView:" + JSON.stringify(user))
			}	
		}
		if(!req.user) {
			res.redirect(this.redirect_url + '?redirected=true&path=' + path)
			return
		}
		if(!(req.user as any).authenticated) {
			res.redirect(this.redirect_url + '?redirected=true&path=' + path)
			return
		} else if((req.user as any).role != "writer" && (req.user as any).role != "admin") {
			req.query.writer = 'false'
			req.query.authenticated = 'true'
		} else {
			req.query.writer = 'true'
			req.query.authenticated = 'true'
		}
		logRequest(req)
		return next()
	}

	isPublicView = async (req : Request,res : Response, next : () => any) => {
		if(this.config.rest.skip_authentication) {
			req.query.writer = 'true'
			return next()
		}
		if(this.config.rest.restricted) {
			return this.isAuthenticatedView(req,res,next)
		}
		if(!req.query) {
			req.query = {}
		}
		try {
			var user = await this.extractAndValidateToken(req) // try authentication by token (overrides session)
		} catch (e) {
			console.error(e)
			res.status(500).send("Internal Server Error")
			return
		}
		if(user) {
			req.user = user
			if(this.config.verbose) {
				console.debug("isPublicView:" + JSON.stringify(user))
			}
		}
		if(!req.user) {
			req.query.public = 'true'
			req.query.writer = 'false'
			req.query.authenticated = 'false'
		} else if (!(req.user as any).authenticated) {
			req.query.public = 'true'
			req.query.writer = 'false'
			req.query.authenticated = 'false'
		} else if((req.user as any).role != "writer" && (req.user as any).role != "admin") {
			req.query.writer = 'false'
			req.query.authenticated = 'true'
		} else {
			req.query.writer = 'true'
			req.query.authenticated = 'true'
		}
		logRequest(req)
		return next()
	}

	isWriter = async (req : Request, res : Response, next : () => any) => {
		if(this.config.rest.skip_authentication) {
			return next()
		}
		try {
			var user = await this.extractAndValidateToken(req) // try authentication by token (overrides session)
		} catch (e) {
			console.error(e)
			res.status(500).send("Internal Server Error")
			return
		}
		if(user) {
			req.user = user
			if(this.config.verbose) {
				console.log("isWriter:" + JSON.stringify(user))
			}
		}
		logRequest(req)
		if(!req.user) {
			if(this.config.verbose) {
				console.log("user not logged in")
			}
			res.status(401).send("Unauthorized")
			return
		}
		if(!(req.user as any).authenticated) {
			if(this.config.verbose) {
				console.log("user not authenticated")
			}
			res.status(401).send("Unauthorized")
			return
		}
		if((req.user as any).role!="writer" && (req.user as any).role!="admin") {
			if(this.config.verbose) {
				console.log("unathorized role")
			}
			res.status(401).send("Unauthorized")
			return
		}
		return next()
	}
		
	isWriterView = async(req : Request, res : Response, next : () => any) => {
		var path = (req.route) ? (req.route.path) ? req.route.path.replace(/^\//,"") : "secciones" : "secciones" ;
		var query_string = ""
		//~ if(req.query && req.query.class) {
			//~ querystring += "&class=" + req.query.class
		//~ }
		if(req.query) {
			if(this.config.verbose) {
				console.log("adding query string")
			}
			query_string += "&" + qs.stringify(req.query)
		} else {
			if(this.config.verbose) {
				console.log("no query string")
			}
		}
		if(this.config.rest.skip_authentication) {
			return next()
		}
		try {
			var user = await this.extractAndValidateToken(req) // try authentication by token (overrides session)
		} catch (e) {
			console.error(e)
			res.status(500).send("Internal Server Error")
			return
		}
		if(user) {
			req.user = user
			if(this.config.verbose) {
				console.log("isWriterView:" + JSON.stringify(user))
			}
		}
		logRequest(req)
		if(!req.user) {
			res.redirect(this.redirect_url + '?redirected=true&path=' + path + query_string)
			return
		}
		if(!(req.user as any).authenticated) {
			res.redirect(this.redirect_url + '?redirected=true&path=' + path  + query_string)
			return
		}
		if((req.user as any).role!="writer" && (req.user as any).role!="admin") {
			if(this.config.verbose) {
				console.log("unathorized role")
			}
			res.redirect(this.redirect_url + '?redirected=true&path=' + path + "&unauthorized=true"  + query_string)
			return
		}
		return next()
	}

	isAdmin = async(req : Request, res : Response, next : () => any) => {
		if(this.config.rest.skip_authentication) {
			return next()
		}
		if(this.config.verbose) {
			console.log({user:req.user})
		}
		try {
			var user = await this.extractAndValidateToken(req) // try authentication by token (overrides session)
		} catch (e) {
			console.error(e)
			res.status(500).send("Internal Server Error")
			return
		}
		if(user) {
			req.user = user
			if(this.config.verbose) {
				console.log("isAdmin:" + JSON.stringify(user))
			}
		}
		logRequest(req)
		if(!req.user) {
			if(this.config.verbose) {
				console.log("user not logged in")
			}
			res.status(401).send("Unauthorized")
			return
		}
		if(!(req.user as any).authenticated) {
			if(this.config.verbose) {
				console.log("user not authenticated")
			}
			res.status(401).send("Unauthorized")
			return
		}
		if((req.user as any).role!="admin") {
			if(this.config.verbose) {
				console.log("unathorized role")
			}
			res.status(401).send("Unauthorized")
			return
		}
		return next()
	}
	
	isAdminView = async (req : Request, res : Response, next : () => any) => {
		var path = (req.route) ? (req.route.path) ? req.route.path.replace(/^\//,"") : "" : "" ;
		var query_string = ""
		if(req.query) {
			if(this.config.verbose) {
				console.log("adding query string")
			}
			query_string += "&" + qs.stringify(req.query)
		} else {
			if(this.config.verbose) {
				console.log("no query string")
			}
		}
		if(this.config.rest.skip_authentication) {
			return next()
		}
		if(this.config.verbose) {
			console.log({user:req.user})
		}
		try {
			var user = await this.extractAndValidateToken(req) // try authentication by token (overrides session)
		} catch (e) {
			console.error(e)
			res.status(500).send("Internal Server Error")
			return
		}
		if(user) {
			req.user = user
			if(this.config.verbose) {
				console.log("isAdminView:" + JSON.stringify(user))
			}
		}
		logRequest(req)
		if(!req.user) {
			res.redirect(this.redirect_url + '?redirected=true&path=' + path + query_string)
			return
		}
		if(!(req.user as any).authenticated) {
			res.redirect(this.redirect_url + '?redirected=true&path=' + path  + query_string)
			return
		}
		if((req.user as any).role!="admin") {
			if(this.config.verbose) {
				console.log("unathorized role")
			}
			res.redirect(this.redirect_url + '?redirected=true&path=' + path + "&unauthorized=true"  + query_string)
			return
		}
		return next()
	}
}

function logRequest(req : Request) {
	var username, authenticated, role 
	if (req.user && (req.user as any).username) {
		username = (req.user as any).username
		authenticated = true
		role = (req.user as any).role
	} else {
		 username = "anonymous"
		 authenticated = false
		 role = "none"
	}
	console.log(req.protocol + " " + req.method + " " + req.originalUrl + " " + username + ":" + authenticated + ":" + role + " " + req.socket.bytesRead)
	return
}
