require('dotenv').config();

module.exports = 
{
  "development": {
      "username": process.env.DB_USER,
      "password": process.env.DB_PASSWORD,
      "database": process.env.DB_DATABASE,
      "host": process.env.DB_HOST,
      "dialect": "postgres",
      "dialectOptions": {
          "ssl": {
              "rejectUnauthorized": false
          }
      }
  },
  "test": {
      "username": "root",
      "password": null,
      "database": "database_test",
      "host": "127.0.0.1",
      "dialect": "postgres"
  },
  "production": {
      "use_env_variable": "DATABASE_URL",
      "dialect": "postgres",
      "protocol": "postgres",
      "dialectOptions": {
          "ssl": {
              "rejectUnauthorized": false
          }
      }
  }
}