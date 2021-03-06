'use strict';
const {
    Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
    class Movie extends Model {
        /**
         * Helper method for defining associations.
         * This method is not a part of Sequelize lifecycle.
         * The `models/index` file will call this method automatically.
         */
        static associate(models) {
            // define association here
            Movie.hasMany(models.MovieCharacter, { foreignKey: "movieId", sourceKey: 'id' });
            Movie.hasMany(models.MovieCategory, { foreignKey: "movieId", sourceKey: 'id' });
            Movie.hasMany(models.Review, { foreignKey: 'movieId', sourceKey: 'id' });
            Movie.hasMany(models.Watchlist, { foreignKey: 'movieId', sourceKey: 'id' })
        }
    };
    Movie.init({
        title: DataTypes.STRING,
        synopsis: DataTypes.STRING,
        rating: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0
        },
        poster: DataTypes.STRING,
        trailer: DataTypes.STRING,
        release_date: DataTypes.STRING,
        budget: DataTypes.STRING,
        director: DataTypes.STRING,
        featured_song: DataTypes.STRING
    }, {
        sequelize,
        modelName: 'Movie',
    });
    return Movie;
};