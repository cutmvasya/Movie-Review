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
      Movie.hasMany(models.MovieCharacter, { foreignKey: "movieId", sourceKey: 'id' } );
      Movie.hasMany(models.MovieCategory, { foreignKey: "movieId", sourceKey: 'id' } );
      Movie.hasOne(models.Movie_Info, { foreignKey: 'movieId', sourceKey: 'id' } );
      Movie.hasMany(models.Review, { foreignKey: 'movieId', sourceKey: 'id' })
    }
  };
  Movie.init({
    title: DataTypes.STRING,
    rating: DataTypes.INTEGER,
    storyline: DataTypes.STRING,
    poster: DataTypes.STRING,
    trailer: DataTypes.STRING
  }, {
    sequelize,
    modelName: 'Movie',
  });
  return Movie;
};