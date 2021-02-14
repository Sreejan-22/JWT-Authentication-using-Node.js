const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const User = require("./model/user");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET =
  "a;ksmfq@#%^4w81903q-ofkmv!#@$^#&^,09768jcmqwopfjm50940*_+*_&^*%3edc";
// this the secret/private key; use any random string
// JWT_SECRET is super sensitive and nobody should have access to this value

mongoose.connect("mongodb://localhost:27017/login-app-db", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});

/*
Node.js body parsing middleware.
Parse incoming request bodies in a middleware before your handlers, available under the req.body property.
*/

const app = express();
app.use(express.static("public"));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
// Returns middleware that only parses json and only looks at requests where the Content-Type
// header matches the type option.

app.get("/", (req, res) => {
  res.render("./public/index");
});

// app.get("/login", (req, res) => {
//   res.render("./public/login");
// });

// the user data containing username and passsword should not be available to people working in the
// organization and so we need to encryption algorithms(password hashing algorithms) that does not store
// the exact password(as plain text). instead it stores a unique value(a hash of that password)
// corresponding to that password, which is impossible for a human being to identify

// some common hasing algorithms are: bcrypt, md5, sha1, sha256, sha512 etc

// There are 2 requirements for password hashing algorithms:
/*
 * Collision should be improbable i.e. it should not happen that 2 different passwords have the same hash values 
 * The hashing algorithm should be slow - why? 
    => A cryptographic hash function used for password hashing needs to be slow to compute because 
    a rapidly computed algorithm could make brute-force attacks more feasible, especially with the 
    rapidly evolving power of modern hardware.
*/

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
  // so we need to find the user through its username only and heck whether it exists or not
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
          // res.status(500).send();
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
            // don't provide any sensitive info to the token as it is visible publicly
            res.json({ status: "ok", data: token });
          } else {
            // password not matching
            res.json({ status: "error", error: "Invalid username/password" });
          }
        }
      });
    }
  });
  // if (await bcryptjs.compare(password, user.password)) {
  //   // if the condition is true, it would mean that password entered is correct

  //   // to obtain the json web token we first need to install the npm package "jsonwebtoken"
  //   const token = jwt.sign(
  //     {
  //       id: (await user)._id,
  //       username: user.username,
  //     },
  //     JWT_SECRET
  //   );
  //   // don't provide any sensitive info to the token as it is visible publicly
  //   res.json({ status: "ok", data: token });
  //   // data is the token
  // }

  // if the compare function returns false return an error message through the response
  // res.json({ status: "error", error: "Invalid username/password" });
});

// register
app.post("/api/register", async (req, res) => {
  // express does not parse the request body by default and thus we need to install body-parser
  // when we are directly sending post requests from the html form instead of sending via json
  // we use express.urlencoded() instead
  const { name, username, password: plaintTextPassword } = req.body;
  //   console.log(req.body);

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
