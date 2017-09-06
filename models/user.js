const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// define our model
const userSchema = new Schema({
  email: {
    type: String,
    unique: true,
    lowercase: true
  },
  password: String
});

//on save hook, encrypt password
//before saving a model this function runs
userSchema.pre('save', function(next) {
  //gets access to user model
  const user = this;

  //generates a salt then runs call back
  bcrypt.genSalt(10, function(err, salt) {
    if(err) { return next(err); }

    //hash out password using the salt
    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if(err) { return next(err); }
      //overwrites plane text password with encrypted password
      user.password = hash;
      next();
    });
  });
});

//compare given password from UI to password in database 
userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if(err) { return done(err); }

    callback(null, isMatch);
  });
}

// create the model class
const ModelClass = mongoose.model('user', userSchema);

// export the model
module.exports = ModelClass;
