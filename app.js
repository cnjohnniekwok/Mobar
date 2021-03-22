require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// Simple login using bycrypt
//-----------------------------------------------------------------|
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

// Using express-session.
// Much place above mongoose.connect.
//-----------------------------------------------------------------|
app.use(session({
  secret: "Authentication Secret.",
  resave: false,
  saveUninitialized: false // <-- false will allow user to leave the site and return with login status, true, will lost session after leaving (bank like sites.)
}));

// Using passport, and initialize passport to deal with session we created above.
// Much place above mongoose.connect.
//-----------------------------------------------------------------|
app.use(passport.initialize());
app.use(passport.session());

// need to use createIndex otherwise its depreated
//-----------------------------------------------------------------|


mongoose.connect("mongodb://" + process.env.DB_HOST + ":" + process.env.DB_PORT + "/" + process.env.DB_NAME, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set('useCreateIndex', true);

const userSchema = mongoose.Schema({
  username: String,
  password: String
});

// add plugin for mongoose userPassword schema.
//-----------------------------------------------------------------|
userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("Userpass", userSchema);

// mongoose serialize and deserialize users
//-----------------------------------------------------------------|
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  //this functino came from passport.
  req.login(user, (err) => {
    if (!err) {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/private");
        // console.log(req.isAuthenticated() + " -- at register");
      });
    } else {
      res.render("login", {
        userAlreadyExisted: "Invalid username or passward.",
        pageTitle: "Login Page",
        authorized: req.isAuthenticated()
      });
    }
  });
  // Simple login using bycrypt
  //-----------------------------------------------------------------|
  // userName = req.body.username;
  // password = req.body.password;
  //
  // UserPass.findOne({
  //   userName: userName
  // }, (err, resultObject) => {
  //   if (!err) {
  //     if (!resultObject) {
  //       res.render('login', {
  //         userAlreadyExisted: "Invalid username or password",
  //         pageTitle: "Login Page"
  //       });
  //     } else {
  //       bcrypt.compare(password, resultObject.password, (err, result) => {
  //         if (!err) {
  //           if(result){
  //             res.render('private', {
  //               pageTitle: "Private"
  //             });
  //           }
  //           else{
  //             res.render('login', {
  //               userAlreadyExisted: "Invalid username or password",
  //               pageTitle: "Login Page"
  //             });
  //           }
  //         } else {
  //           console.log("An error found -: " + err);
  //         }
  //       });
  //     }
  //   } else {
  //     console.log("An error found -: " + err);
  //   }
  // });

});
app.post("/register", (req, res) => {
  // This function came from passport mongoose
  User.register({
    username: req.body.username
  }, req.body.password, (err, user) => {
    if (!err) {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/private");
        // console.log(req.isAuthenticated() + " -- at register");
      });
    } else {
      console.log(err);
      res.render("register", {
        userAlreadyExisted: "Something went worng, please try again...",
        pageTitle: "Registration",
        authorized: req.isAuthenticated()
      });
    }
  });

  // Simple login using bycrypt
  //-----------------------------------------------------------------|
  // userName = req.body.username;
  // password = req.body.password;
  // UserPass.findOne({
  //   userName: userName
  // }, (err, resultObject) => {
  //   if (!err) {
  //     if (!resultObject) {
  //
  //       bcrypt.hash(password, saltRounds, (err, hash) => {
  //         if (!err) {
  //           let userPassDoc = new UserPass({
  //             userName: req.body.username,
  //             password: hash
  //           });
  //           userPassDoc.save((err) => {
  //             if (!err) {
  //               console.log("Registered.");
  //               res.render('login', {
  //                 userAlreadyExisted: "",
  //                 pageTitle: "Login Page"
  //               });
  //             } else {
  //               console.log("An error found -: " + err);
  //             }
  //           });
  //         } else {
  //           console.log("An error found -: " + err);
  //         }
  //       });
  //
  //     } else {
  //       res.render('register', {
  //         userAlreadyExisted: "Email already used.",
  //         pageTitle: "Registration"
  //       });
  //     }
  //   } else {
  //     console.log("An error found -: " + err);
  //   }
  // });
});

// /private route relies on passport to authenticate
//-----------------------------------------------------------------|
app.get("/private", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("private", {
      pageTitle: "Authenticated!",
      authorized: req.isAuthenticated()
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/register", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("private", {
      pageTitle: "Authenticated!",
      authorized: req.isAuthenticated()
    });
  } else {
    res.render("register", {
      userAlreadyExisted: "",
      pageTitle: "Registration",
      authorized: req.isAuthenticated()
    });
  }
});

app.get("/login", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("private", {
      pageTitle: "Authenticated!",
      authorized: req.isAuthenticated()
    });
  } else {
    res.render("login", {
      userAlreadyExisted: "",
      pageTitle: "Login Page",
      authorized: req.isAuthenticated()
    });
  }
});

app.get("/", (req, res) => {
  res.render("home", {
    loggedout: "",
    pageTitle: "Welcome",
    authorized: req.isAuthenticated()
  });
});

app.get("/logout", (req, res)=>{
  //This came from passport
  req.logout();
  res.render("home", {
    loggedout: "You have successfully logged out.",
    pageTitle: "Welcome",
    authorized: req.isAuthenticated()
  });

});

app.listen(process.env.SERVER_LISTEN_PORT, (err) => {
  console.log("Server is successfully running at prot -: " + process.env.SERVER_LISTEN_PORT);
});
