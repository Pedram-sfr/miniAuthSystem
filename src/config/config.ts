import { registerAs } from "@nestjs/config";

export enum ConfigKeys {
    App = "App",
    Db = "Db",
    Jwt = "Jwt"
}

const AppConfig = registerAs(ConfigKeys.App, () => ({
    port: 3000
}))
const JwtConfig = registerAs(ConfigKeys.Jwt, () => ({
    accessTokenSecret: "c933ca55e84663f81855951296810b42986cfa6ad43061f4ece3c0791a1a9574",
    refreshTokenSecret: "18eca02b3ffa50dd25b73956a4c5781dfc53f0189eeb25ac49a3287d4b1abb51",
}))
const DbConfig = registerAs(ConfigKeys.Db, () => ({
    port: 5432,
    host: "localhost",
    username: "postgres",
    password: "33185502",
    database: "auth-otp"
}))

export const configurations = [AppConfig, DbConfig, JwtConfig]