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
//                      DEMO PAGE RENDERER
//-----------------------------------------------------------------|
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

function renderLoginPage(req, res, renderMessage){
  res.render("login", {
    userAlreadyExisted: renderMessage,
    pageTitle: "Login Page",
    username: "",
    authorized: req.isAuthenticated()
  });
}

function renderRegisterPage(req, res, renderMessage){
  res.render("register", {
    userAlreadyExisted: renderMessage,
    pageTitle: "Registration",
    username: "",
    authorized: req.isAuthenticated()
  });
}
//=================================================================|
//                      DEMO SITE POST ROUTE
//-----------------------------------------------------------------|
//reference: http://www.passportjs.org/docs/authenticate/
app.post("/login", (req, res, next) => {
  // Create user document for checking
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      console.log(err);
    }

    if (!user) {
      renderLoginPage(req, res, "Invalid login credentials.");
    }
    else {
      req.logIn(user, (err) => {
        if (err) {
          console.log(err);
        }
        else {
          return res.redirect("/private");
        }
      });
    }
  })(req, res, next);
});

app.post("/register", (req, res) => {
  // This function came from passport mongoose
  User.register({ username: req.body.username }, req.body.password, (err, user) => {
    if (err) {
      console.log(err);
      renderRegisterPage(req, res, "Email already in use.");
    }
    else{
      passport.authenticate("local")(req, res, () => { res.redirect("/private"); });
    }
  });
});

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
            if(!err){renderLoginPage(req, res, "Password updated, please login again.")}
            else{renderSettingPage(req, res, "Somehting went wrong, please try again...");}
          });
        }
        else{renderSettingPage(req, res, "User does not exist in our record, please signout and try again.");}
      }
      else{renderSettingPage(req, res, "Somehting went wrong, please try again...");}
    });
  }
  else{renderSettingPage(req, res, "Both columns of new password must be the same.");}
});
//=================================================================|
//                      DEMO SITE GET ROUTE
//-----------------------------------------------------------------|
app.get("/", (req, res) => {
  res.redirect("/home");
});

app.get("/home", (req, res) => {
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
  } else { res.redirect("/login"); }
});

app.get("/register", (req, res) => {
  if (req.isAuthenticated()) { res.redirect("/private"); }
  else {
    res.render("register", {
      userAlreadyExisted: "",
      pageTitle: "Registration",
      username: "",
      authorized: req.isAuthenticated()
    });
  }
});

app.get("/login", (req, res) => {
  if (req.isAuthenticated()) { res.redirect("/private"); }
  else {
    res.render("login", {
      userAlreadyExisted: "",
      pageTitle: "Login Page",
      authorized: req.isAuthenticated()
    });
  }
});

app.get("/settings", (req, res) => {
  if (req.isAuthenticated()) {
    renderSettingPage(req, res, "");
  }
  else { res.redirect("/login"); }
});

app.get("/logout", (req, res) => {
  //This came from passport
  if(req.session){
    req.logout();
    req.session.destroy((err) => {
      if(err){ console.log(err); }
      else{
        res.clearCookie('session-id');
        res.redirect("/");
      }
    });

  }
});

app.get("*", (req, res) => {
  res.status(404).render("notfound",{
    pageTitle: "4o4 NoT FoUnD",
    authorized: req.isAuthenticated()
  });
});

app.listen(process.env.PORT, (err) => {
  console.log("Server is successfully running at prot -: " + process.env.PORT);
});
