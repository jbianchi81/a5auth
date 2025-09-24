import {setGlobal, baseModel} from 'a5base'
const g = setGlobal.default()
const pool = g.pool
const config = g.config
import { createHash } from 'crypto'    
const internal = {}
import { parse } from 'csv-string'
import {Request, Response} from 'express'
// API

export async function getUsers(req : Request, res : Response) {
    if(!pool) {
        throw new Error("pool not initialized")
    }
    return pool.query("SELECT id,name,role from users order by id")
    .then(result=>{
        res.send(result.rows)
    })
    .catch(e=>{
        console.error(e)
        res.status(400).send(e.toString())
    })
}

export async function createUser(req : Request,res : Response) {    // ?password=&role=reader
    var password = (req.query && req.query.password) ? req.query.password : (req.body && req.body.password) ? req.body.password : undefined
    var role = (req.query && req.query.role) ? req.query.role : (req.body && req.body.role) ? req.body.role : undefined
    var token = (req.query && req.query.token) ? req.query.token : (req.body && req.body.token) ? req.body.token : undefined
    const user = new User({
        name: req.params.username,
        role: role,
        password: password,
        token: token
    })
    return user.create()
       .then(users=>{
        if(!users || !users.length) {
            res.status(400).send("Error: no user updated")
            return
        }
        if(req.headers['content-type'] == "multipart/form-data" || req.headers['content-type'] == "application/x-www-form-urlencoded") {
            if(users[0]) {
                console.log(users[0])
                var data = users[0]
                data.base_url = config.rest.base_url
                res.render('user_updated',data)
            } else {
                res.status(400).send("Error: no user updated")
            }
        } else {
            res.send(users)
        }
    })
    .catch(e=>{
        console.error(e)
        res.status(400).send(e.toString())
    })
}

internal.getUser = function (req,res) {
    if(! req.params) {
        res.status(400).send("missing params")
        return
    }
    if(req.user.role!="admin" && req.params.username!=req.user.username) {
        res.status(408).send("Unauthorized")
        return
    }
    pool.query("SELECT id,name,role from users where name=$1",[req.params.username])
    .then(result=>{
        res.send(result.rows)
    })
    .catch(e=>{
        console.error(e)
        res.status(400).send(e.toString())
    })
}

internal.userChangePassword = function (req,res) {
    if(!req.body) {
        res.status(400).send("missing parameters")
        return
    }
    if(!req.body.username) {
        res.status(400).send("username missing")
        return
    }
    if(req.user.role!="admin" && req.body.username!=req.user.username) {
        res.status(408).send("Unauthorized")
        return
    }
    pool.query("select * from users where name=$1",[req.body.username])
    .then(result=>{
        if(!result.rows || result.rows.length==0) {
            res.status(400).send("User not found")
            return
        }
        var old_user = result.rows[0]
        if(req.user.role!="admin" && old_user.protected) {
            res.status(401).send("User protected")
            return
        }
        var query
        if(!req.body.newpassword) {
            if(!req.body.newtoken) {
                res.status(400).send("New password and/or token missing")
                return
            }
            if(req.body.newtoken == "") {
                res.status(400).send("New token is empty string")
                return
            }
            query = pool.query("UPDATE users SET token=$1 WHERE name=$2 RETURNING name,pass_enc,token,role",[createHash('sha256').update(req.body.newtoken).digest('hex'),req.body.username])
        } else if (req.body.newtoken && req.body.newtoken != "") {
            query = pool.query("UPDATE users SET pas_enc=$1, token=$2 WHERE name=$3 RETURNING name,pass_enc,token,role",[createHash('sha256').update(req.body.newpassword).digest('hex'),createHash('sha256').update(req.body.newtoken).digest('hex'),req.body.username])
        } else {
            query = pool.query("UPDATE users set pass_enc=$1 where name=$2 RETURNING name,pass_enc,role",[createHash('sha256').update(req.body.newpassword).digest('hex'),req.body.username])
        }
        return query.then(result=>{
            if(!result) {
                res.status(400).send("Input error")
                return
            }
            if(result.rows.length==0) {
                res.status(400).send("Nothing updated")
                return
            }
            if(req.headers['content-type'] == "multipart/form-data" || req.headers['content-type'] == "application/x-www-form-urlencoded") {
                var data = result.rows[0]
                data.base_url = config.rest.base_url
                res.render('user_updated',data)
            } else {
                //~ console.log({user:result.rows[0]})
                res.send("Password y/o token actualizado")
            }
        })
    })
    .catch(e=>{
        console.error(e)
        res.status(400).send(e.toString())
    })
}

internal.deleteUser = async function (req,res) {
    if(!req.params || !req.params.username) {
        res.status(400).send("parameter username missing")
        return
    }
    const users = await internal.user.delete({name:req.params.username})
    if(!users || users.length==0) {
        res.status(400).send("User " + req.params.username + " not found")
        return
    }
    console.log({deletedUsers:users})
    res.send("User " + users[0].name + " deleted")
    return
}

// GUI

internal.viewUser = function (req,res) {
    var username = req.params.username
    if(!req.user || username != req.user.username) {
        if(!config.rest.skip_authentication && (!req.user || req.user.role!="admin")) {
            res.status(408).send("Must be admin to enter this user's config")
            return
        }
        console.log("admin entering " + username + " config")
    } else {
        console.log("user " + username + " entering config")
    } 
    pool.query("SELECT id,name username,role,protected from users where name=$1",[username])
    .then(result=>{
        if(result.rows.length==0) {
            res.status(404).send("user not found")
            return
        }
        var data = {user:result.rows[0],loggedAs: (req.user) ? req.user.username : undefined, isAdmin: (req.user && req.user.role == "admin"), protected: ((!req.user || req.user.role != "admin") && result.rows[0].protected), base_url: config.rest.base_url}
        res.render('usuario',data)
    })
    .catch(e=>{
        console.error(e)
        res.status(400).send(e.toString())
    })
}
internal.viewUsers = function (req,res) {
    pool.query("SELECT id,name username,role from users order by id")
    .then(result=>{
        if(result.rows.length==0) {
            // res.status(404).send("users not found")
            console.debug("No users found")
            // return
        }
        var data = {users:result.rows,loggedAs: (req.user) ? req.user.username : undefined, base_url: config.rest.base_url}
        res.render('usuarios',data)
    })
    .catch(e=>{
        console.error(e)
        res.status(400).send(e.toString())
    })
}

internal.newUserForm = function(req,res) {
    var data = {loggedAs: (req.user) ? req.user.username : undefined, base_url: config.rest.base_url}
    res.render('usuarionuevo',data)
}

export class User extends baseModel.baseModel {

    name : string

    id : number | undefined

    role : string | undefined

    password: string | undefined

    pass_enc: Buffer<ArrayBufferLike> | undefined

    token: Buffer<ArrayBufferLike>  | undefined

    static _fields = {
        id: {
            type: "integer"
        },
        name: {
            type: "string"
        },
        role: {
            type: "string"
        },
        password: {
            type: "string"
        },
        pass_enc: {
            type: "buffer"
        },
        token: {
            type: "any"
        }
    }
    constructor(fields : {id?: number, name: string, role?: string, password?: string, pass_enc?: Buffer<ArrayBufferLike>, token?: Buffer<ArrayBufferLike> }) {
        super(fields)
        this.id = fields.id
        this.name = fields.name
        this.role = fields.role
        this.password = fields.password
        this.pass_enc = fields.pass_enc
        this.token = fields.token
    }
    bufferToString(buffer : Buffer) {
        return Buffer.from(buffer).toString()
    }
    stringifyPassword() {
        if(this.pass_enc) {
            return this.bufferToString(this.pass_enc)
        } else {
            return ""
        }
    }
    stringifyToken() {
        if(this.token) {
            if(typeof this.token == 'string') {
                return this.token
            } else {
                return this.bufferToString(this.token)
            }
        } else {
            return ""
        }
    }
    toCSV(options : {header?: boolean}={}) {
        if(options.header) {
            var header = "id,name,role,password,pass_enc,token\n"
        } else {
            var header = ""
        }
        return `${header}${(this.id) ? this.id : ""},${this.name},${this.role},${(this.password) ? this.password : ""},${this.stringifyPassword()},${this.stringifyToken()}`
    }
    static fromCSVMany(csv_string : string) {
        const data = parse(csv_string)
        return data.map(r=>{
            return this.fromCSV(r) 
        })
    }
    /**
     * Convert CSV row to user instance 
     * @param {string|any[]} array_or_string - Array or delimited string that represents a single user instance
     * @returns {internal.user}
     */
    static fromCSV(array_or_string : string[] | string) : User {
        let values : string[]
        if(!Array.isArray(array_or_string)) {
            const parsed = parse(array_or_string)
            if(!parsed.length || !parsed[0]) {
                throw new Error("Parsed string resulted in no items")
            }
            values = parsed[0]         
        } else {
            values = array_or_string
        }
        if(values.length<6) {
            throw new Error("Invalid user csv: need 6 columns")
        }
        return new User({
            id: (values[0] != "") ? parseInt(values[0] as string) : undefined,
            name: values[1],
            role: values[2],
            password: (values[3] != "") ? values[3] : undefined,
            pass_enc: (values[4] != "") ? Buffer.from(values[4]!) : undefined,
            token: (values[5] != "") ? Buffer.from(values[5]!) : undefined
        })
    }

    toJSON() {
        return {
            id: this.id,
            name: this.name,
            role: this.role,
            password: this.password,
            token: this.token,
            pass_enc: this.pass_enc
        }
    }
    encryptToken() {
        return (this.token) ? (typeof this.token == "string") ? createHash('sha256').update(this.token).digest('hex') : Buffer.from(this.token) : undefined
    }
    encryptPassword() {
        return (this.password) ? createHash('sha256').update(this.password).digest('hex') : (this.pass_enc) ? Buffer.from(this.pass_enc) : undefined
    }
    async create() {
        if(!pool) {
            throw new Error("Pool not initialized")
        }
        // console.log(this)
        var pass_enc = this.encryptPassword()
        var token = this.encryptToken()
        const result = await pool.query("SELECT name,encode(pass_enc,'escape') pass_enc_esc from users where name=$1",[this.name])
        if(result.rows.length==0) {
            if(!pass_enc || !this.role) { //} || !token) {
                throw "Required: password, role" // o token"
            }
            var inserted = await pool.query("INSERT INTO users (name,pass_enc,role,token) VALUES ($1,$2,coalesce($3,'reader'),$4) RETURNING name,pass_enc,role,token",[this.name, pass_enc, this.role, token])
        } else {
            var inserted = await pool.query("UPDATE users set pass_enc=coalesce($1,pass_enc), role=coalesce($2,role), token=coalesce($4,token) where name=$3 RETURNING name,pass_enc,role,token",[pass_enc, this.role, this.name, token])
        }
        if(!inserted.rows.length) {
            console.error("creation failed")
            return
        }
        this.name = inserted.rows[0].name
        this.pass_enc = inserted.rows[0].pass_enc
        this.role = inserted.rows[0].role
        this.token = inserted.rows[0].token
        return this
    }
    static async create(users,options,client) {
        users = (Array.isArray(users)) ? users.map(u=>new internal.user(u)) : [new internal.user(users)]
        const created = []
        for(var i in users) {
            created.push(await users[i].create())
        }
        return created
    }
    static async read(filter={},options,client) {
        const result = await pool.query("SELECT id,name,role,pass_enc,token from users order by id")
        const users = result.rows.map(r=> new internal.user(r))
        if(filter.id) {
            var matches = users.filter(u=>u.id == filter.id)
            if(!matches.length) {
                console.error("Couldn't find user")
                return
            }
            return matches[0]
        } else if (filter.name) {
            var matches = users.filter(u=>u.name == filter.name)
            if(!matches.length) {
                console.error("Couldn't find user")
                return
            }
            return matches[0]
        } else if (filter.role) {
            var matches = users.filter(u=>u.role == filter.role)
            if(!matches.length) {
                console.error("Couldn't find users")
                return []
            }
            return matches
        }
        return users
    }
    async update(changes={},client) {
        const valid_keys = ["password","token","role"]
        Object.keys(changes).forEach(key=>{
            if(valid_keys.indexOf(key) < 0) {
                throw(`Invalid update key ${key}`)
            }
            this[key] = changes[key]
        })
        return this.create()
    }
    static async update(filter={},changes={},client) {
        const users = await internal.user.read(filter)
        const updated = []
        if(Array.isArray(users))    {
            for(var i in users) {
                updated.push(await users[i].update(changes,client))
            }
        } else {
            updated.push(await users.update(changes,client))
        }
        return updated
    }
    async delete(options,client) {
        const deleted = await pool.query("DELETE FROM users WHERE name=$1 RETURNING id,name,role",[this.name])
        if(deleted.rows.length) {
            return new internal.user(deleted.rows[0])
        } else {
            console.error("Nothing deleted")
            return
        }
    }
    static async delete(filter,options,client) {
        const users = await internal.user.read(filter,undefined,client)
        // console.log(users)
        const deleted = []
        if(Array.isArray(users)) {
            for(var i in users) {
                console.log("Deleting user " + users[i].name)
                deleted.push(await users[i].delete(options,client))
            }
        } else {
            return users.delete(options,client)
        }
        return deleted
    }    
}

export default internal