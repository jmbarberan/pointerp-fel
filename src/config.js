require('dotenv').config()

const config = {
    db: {
        host: "localhost",
        user: "root",
        password: "jb",
        database: "pop",
        port: "3306",
        connectTimeout: 60000
    },
    dbsubscripciones: {
        host: process.env.SDB_HOST || "localhost",
        user: process.env.SDB_USER || "postgres",
        password: process.env.SDB_PASS || "jb",
        database: process.env.SDB_NAME || "base",
        port: process.env.SDB_PORT || "5432"
    },
    dbsubscripciones_schema: process.env.SDB_SCHEMA || "subscripciones",
    server: {
        port: 3000
    },
    jsonSpaces: 2
};
  
module.exports = config;