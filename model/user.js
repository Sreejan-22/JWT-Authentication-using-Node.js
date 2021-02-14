const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

// note the unique property in the username object; it means that each username must be unique;
// this uniqueness check is done with the help of indexing in mongodb and mongoose doesn't manually check whether
// the usernames are unique

const user = mongoose.model("User", userSchema);
module.exports = user;
