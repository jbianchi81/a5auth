import type { Express, Request, Response } from 'express';
import { Pool } from 'pg';
import passport from 'passport';
import filestore from 'session-file-store';
export { User } from './userAdmin';
export interface AuthenticationConfig {
    rest: {
        index: any;
        restricted: any;
        cookieMaxAge: any;
        redirect_url?: string;
        secure?: boolean;
        session_file_store?: string;
        skip_authentication?: boolean;
    };
    verbose?: boolean;
}
export declare class AuthUser {
    username: string;
    password: string;
    role: string;
    id: string;
    token: string;
    verbose?: boolean | undefined;
    authenticated: boolean;
    constructor(user: {
        name: string;
        password: string;
        role: string;
        id: string;
        token: string;
        verbose?: boolean;
    });
    authenticate: (password: string) => boolean;
}
export declare function tokenExtractor(req: Request): string | null;
export default class Authentication {
    app: Express;
    config: AuthenticationConfig;
    pool: Pool;
    redirect_url: string;
    FileStore: filestore.FileStore;
    passport: passport.PassportStatic;
    constructor(app: Express, config: AuthenticationConfig, pool: Pool);
    authenticate: (user: AuthUser, password: string) => boolean;
    loginReject: (req: Request, mensaje: string, done: (arg0: null, arg1: boolean, arg2: {
        message: string;
    }) => any) => any;
    validateToken: (token: string) => Promise<AuthUser | undefined>;
    extractAndValidateToken: (req: Request, verbose?: boolean) => Promise<AuthUser | undefined>;
    loadOne: (username: string) => Promise<AuthUser | undefined>;
    findById: (id: number) => Promise<AuthUser | undefined>;
    findByJWT: (token: string) => Promise<AuthUser | undefined>;
    isAuthenticated: (req: Request, res: Response, next: () => any) => Promise<any>;
    isPublic: (req: Request, res: Response, next: () => any) => Promise<any>;
    isAuthenticatedView: (req: Request, res: Response, next: () => any) => Promise<any>;
    isPublicView: (req: Request, res: Response, next: () => any) => Promise<any>;
    isWriter: (req: Request, res: Response, next: () => any) => Promise<any>;
    isWriterView: (req: Request, res: Response, next: () => any) => Promise<any>;
    isAdmin: (req: Request, res: Response, next: () => any) => Promise<any>;
    isAdminView: (req: Request, res: Response, next: () => any) => Promise<any>;
}
