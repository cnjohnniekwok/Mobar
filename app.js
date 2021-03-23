require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// Initalize app using express
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

//=================================================================|
//                      DEMO SITE POST ROUTE
//-----------------------------------------------------------------|
app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  //this function came from passport.
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
        username: req.session.passport.user,
        authorized: req.isAuthenticated()
      });
    }
  });
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
        username: req.session.passport.user,
        authorized: req.isAuthenticated()
      });
    }
  });
});

function renderSettingPage(req, res, renderMessage){
  res.render("settings", {
    userAlreadyExisted: renderMessage,
    pageTitle: "Settings",
    username: req.session.passport.user,
    authorized: req.isAuthenticated()
  });
}

function renderPrivatePage(req ,res){
  res.render("private", {
    pageTitle: "Authenticated!",
    username: req.session.passport.user,
    authorized: req.isAuthenticated()
  });
}

app.post("/settings", (req, res)=>{
  const currentUser = req.session.passport.user;
  const oldPassword = req.body.oldPassword;
  const newPassword = req.body.newPassword;
  const confirmPswd = req.body.confirmPswd;
  if(newPassword === confirmPswd){
    User.findOne({username:currentUser}, (err, resultObject)=>{
      if(!err){
        if(resultObject){
          resultObject.changePassword(oldPassword, newPassword, (err)=>{
            if(!err){
              res.render("login", {
                userAlreadyExisted: "Password updated, please login again.",
                pageTitle: "Login Page",
                username: req.session.passport.user,
                authorized: req.isAuthenticated()
              });
            }
            else{
              renderSettingPage(req, res, "Somehting went wrong, please try again...");
            }
          });
        }
        else{
          renderSettingPage(req, res, "User does not exist in our record, please signout and try again.");
        }
      }
      else{
        renderSettingPage(req, res, "Somehting went wrong, please try again...");
      }
    });
  }
  else{
    renderSettingPage(req, res, "Both columns of new password must be the same.");
  }

});
//=================================================================|
//                      DEMO SITE GET ROUTE
//-----------------------------------------------------------------|

app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("home", {
      loggedout: "",
      pageTitle: "Welcome",
      username: req.session.passport.user,
      authorized: req.isAuthenticated()
    });
  }
  else{
    res.render("home", {
      loggedout: "",
      pageTitle: "Welcome",
      username: "",
      authorized: req.isAuthenticated()
    });
  }

});

// "/private" route relies on passport to authenticate
//-----------------------------------------------------------------|
app.get("/private", (req, res) => {
  if (req.isAuthenticated()) {
    renderPrivatePage(req, res);
  } else {
    res.redirect("/login");
  }
});

app.get("/register", (req, res) => {
  if (req.isAuthenticated()) {
    renderPrivatePage(req, res);
  } else {
    res.render("register", {
      userAlreadyExisted: "",
      pageTitle: "Registration",
      username: "",
      authorized: req.isAuthenticated()
    });
  }
});

app.get("/login", (req, res) => {
  if (req.isAuthenticated()) {
    renderPrivatePage(req, res);
  } else {
    res.render("login", {
      userAlreadyExisted: "",
      pageTitle: "Login Page",
      username: "",
      authorized: req.isAuthenticated()
    });
  }
});

app.get("/logout", (req, res)=>{
  //This came from passport
  req.logout();
  res.render("home", {
    loggedout: "You have successfully logged out.",
    pageTitle: "Welcome",
    username: "",
    authorized: req.isAuthenticated()
  });
});

app.get("/settings", (req, res) => {
  if (req.isAuthenticated()) {
    renderSettingPage(req, res, "");
  } else {
    res.redirect("/login");
  }
});

app.listen(process.env.PORT, (err) => {
  console.log("Server is successfully running at prot -: " + process.env.PORT);
});
