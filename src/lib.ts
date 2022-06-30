import { Handler } from "express";
import { auth, claimCheck, JWTPayload } from "express-oauth2-jwt-bearer";

export interface User {
  sub: string;
  claims: JWTPayload;
  permissions: string[];
}
declare global {
  namespace Express {
    export interface Request {
      user: User;
    }
  }
}

declare module "express-oauth2-jwt-bearer" {
  export interface JWTPayload {
    permissions: string[];
  }
}

type Token = string;
type Permissions = string[] | string[][];

export type Config = {
  issuer: string;
  audience: string;
  jwksUri: string;
  algorithms: string[];
};

function getConfigurationFromEnv(): Config {
  return {
    issuer: process.env.AUTH0_ISSUER!,
    jwksUri: process.env.AUTH0_JWKS_URI!,
    audience: process.env.AUTH0_AUDIENCE!,
    algorithms: process.env.AUTH0_ALGORITHMS?.split(",").map((t) => t.trim())!,
  };
}

const extractClaims: Handler = (req, res, next) => {
  const check = claimCheck((claims) => {
    req.user = {
      claims,
      permissions: claims.permissions,
      sub: claims.sub ?? "",
    };

    return true;
  });

  check(req, res, next);
};

export function authenticated(
  permissions?: Permissions,
  config?: Config
): Handler[] {
  if (config === undefined) {
    config = getConfigurationFromEnv();
  }

  const authCheck = auth({
    audience: config.audience,
    issuer: config.issuer,
    jwksUri: config.jwksUri,
  });

  return [
    authCheck,
    extractClaims,
    permissions
      ? checkPerm(permissions)
      : (req, res, next) => {
          next();
        },
  ];
}

export function checkPerm(permissions: Permissions): Handler {
  return (req, res, next) => {
    const userPermissions = req.user.claims.permissions;

    let check: string[][];

    if (typeof permissions[0] === "string") {
      check = [permissions as string[]];
    } else {
      check = permissions as string[][];
    }

    const allowed = check.some((perms) =>
      perms.every((perm) => userPermissions.includes(perm))
    );

    if (allowed) {
      next();
    } else {
      res.status(403).json({
        error:
          "You do not have the required permissions to perform this action.",
      });
    }
  };
}
