const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const User = require("./model/user");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET =
  "a;ksmfq@#%^4w81903q-ofkmv!#@$^#&^,09768jcmqwopfjm50940*_+*_&^*%3edc";

mongoose.connect("mongodb://localhost:27017/login-app-db", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});

const app = express();
app.use("/", express.static(path.join(__dirname, "public")));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

//change password
app.post("/api/change-password", async (req, res) => {
  // get the token
  const { token, newPassword: plaintTextPassword } = req.body;

  if (!plaintTextPassword || typeof plaintTextPassword !== "string") {
    res.json({ status: "error", error: "Invalid Password" });
  }

  if (plaintTextPassword.length < 6) {
    res.json({
      status: "error",
      error: "Password should contain atleast 6 characters",
    });
  }

  // verify the token
  try {
    const user = jwt.verify(token, JWT_SECRET);
    const _id = user.id;

    const hashedPassword = await bcryptjs.hash(plaintTextPassword, 10);

    await User.updateOne(
      { _id },
      {
        $set: { password: hashedPassword },
      }
    );
    // console.log("JWT decoded: ", user);
  } catch (err) {
    res.json({ status: "error", error: "Security alert!!" });
  }
  // refer: https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback
  res.json({ status: "ok" });
});

// login
app.post("/api/login", async (req, res) => {
  /* we can't compare the entered password with the one stored in the database as it is a hashed version of 
  the plain text password. also we cannot store the hashed version of the password entered and then compare
  with the stored version because for the same password, bcrypt generates a different hash string at different
  times
  */
  // so we need to find the user through its username only and check whether it exists or not
  // if it exists, use an inbuilt bcrypt function to check if the password entered by the user is correct or not
  User.findOne({ username: req.body.username }, (err, data) => {
    if (err) {
      console.log(err);
      res.json({ status: "error", error: "An error occurred" });
    } else {
      if (!data) {
        // username does not exist
        res.json({ status: "error", error: "Invalid username/password" });
      }
      bcryptjs.compare(req.body.password, data.password, (err, result) => {
        if (err) {
          console.log(err);
          res.json({ status: "error", error: "An error occurred" });
        } else {
          if (result) {
            // if result is true it would mean that the correct password was entered
            const token = jwt.sign(
              {
                id: data._id,
                username: data.username,
              },
              JWT_SECRET
            );
            res.json({ status: "ok", data: token });
          } else {
            // password not matching
            res.json({ status: "error", error: "Invalid username/password" });
          }
        }
      });
    }
  });
});

// register
app.post("/api/register", async (req, res) => {
  const { name, username, password: plaintTextPassword } = req.body;

  // checks on username and password
  if (!username || typeof username !== "string") {
    res.json({ status: "error", error: "Invalid Username" });
  }

  if (!plaintTextPassword || typeof plaintTextPassword !== "string") {
    res.json({ status: "error", error: "Invalid Password" });
  }

  if (plaintTextPassword.length < 6) {
    res.json({
      status: "error",
      error: "Password should contain atleast 6 characters",
    });
  }

  const password = await bcryptjs.hash(plaintTextPassword, 10);

  // create a new user
  const userData = {
    name,
    username,
    password,
  };
  const user = User.create(userData, (err, data) => {
    if (err) {
      //   console.log(JSON.stringify(err));
      if (err.code === 11000) {
        // duplicate username => 11000 is the code for duplicate error in mongodb (when we specify
        //  in the schema, unique: true)
        res.json({ status: "error", error: "Username already exists" });
      } else {
        throw error;
      }
    } else {
      console.log("User: ", data);
      res.json({ status: "ok" });
    }
  });
});

app.listen(3000, () => {
  console.log("Server running at port 3000");
});
