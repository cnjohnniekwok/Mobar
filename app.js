
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate"); // just to make findOrCreate work.
const GoogleStrategy = require("passport-google-oauth20").Strategy; // Google OAuth20
const GitHubStrategy = require("passport-github2").Strategy; // passport-github2;
const HttpsProxyAgent = require('https-proxy-agent'); //proxy... just need to do this anyway..
const multer = require('multer'); //for image uploading use.

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
  password: String,
  googleId : String,
  githubId : String,
  displayName: String,
  profession: String,
  memberName: String,
  emailAddr: String,
  phoneNumber: String,
  experience: String,
  projectCount: String,
  language: String,
  availability: String,
  bio: String,
  pay: String
});

const imageSchema = new mongoose.Schema({
  userID: String,
  name: String,
  img:{
    data: Buffer,
    contentType: String
  }
});

// add plugin for mongoose userPassword schema.
// add plugin for findOrCreate package
//-----------------------------------------------------------------|
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// User database mongoDB mongoose model
//-----------------------------------------------------------------|
const User = mongoose.model("User", userSchema);
const ImageModel = new mongoose.model('Image', imageSchema);

//=================================================================|
//                      IMAGE UPLOAD STORAGE
//-----------------------------------------------------------------|
let storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads')
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now())
    }
});

let upload = multer({ storage: storage });
//=================================================================|
//                     PASSPORT STRATEGY
//-----------------------------------------------------------------|
// mongoose serialize and deserialize users
//-----------------------------------------------------------------|
passport.use(User.createStrategy()); // authenticate("local")
passport.serializeUser( (user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});

// Using Passport Google Open Authentication 2.0
//-----------------------------------------------------------------|
const googleOAuth20Strategy = new GoogleStrategy({ // authenticate("google")
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://" + process.env.SR_HOST + ":" + process.env.PORT + "/auth/google/private",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  (accessToken, refreshToken, profile, cb) => {
     console.log(profile); // create user profile id from this callback function from passport google OAuth 2.
    User.findOrCreate({ googleId: profile.id, displayName: profile.displayName}, (err, user) => {
      return cb(err, user);
    });
  }
)

// Using Passport Github Open Authentication 2.0
//-----------------------------------------------------------------|
const githubOAuth20Strategy = new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://" + process.env.SR_HOST + ":" + process.env.PORT + "/auth/github/private",
  },
  (accessToken, refreshToken, profile, done) => {
     console.log(profile);
    User.findOrCreate({ githubId: profile.id, displayName: profile.displayName,  username:profile.username }, (err, user) => {
      return done(err, user);
    });
  }
)

// Set Google OAuth to use proxy agent HTTP_PROXY=http://<proxyUser>:<proxyPass>@<proxyURL>:<proxyPort>
// Comment this out if no proxy needed.
// reference: https://github.com/drudge/passport-facebook-token/issues/67
// restart application server to apply proxy change
//-----------------------------------------------------------------|
// const proxyAgent = new HttpsProxyAgent(process.env.HTTP_PROXY);
//
// // Set proxy agent to OAuth Strategies
// //-----------------------------------------------------------------|
// googleOAuth20Strategy._oauth2.setAgent(proxyAgent);
// githubOAuth20Strategy._oauth2.setAgent(proxyAgent);

// Set Passport to use Strategies
//-----------------------------------------------------------------|
passport.use(googleOAuth20Strategy);
passport.use(githubOAuth20Strategy);

// For proxy setting
//=================================================================|
//                      DEMO PAGE RENDERER
//-----------------------------------------------------------------|
function renderSettingPage(req, res, renderMessage){
  if(mongoose.connection.readyState === 1){ // 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting
    User.findOne({_id:req.session.passport.user},(err,resultObject)=>{
      if(err){
        console.log(err);
      }
      else{
        if(resultObject){
            console.log(resultObject);
            let dropDownListName  = resultObject.username;
            let profession        = resultObject.profession;
            let memberName        = resultObject.memberName;
            let emailAddr         = resultObject.emailAddr;
            let phoneNumber       = resultObject.phoneNumber;
            let experience        = resultObject.experience;
            let projectCount      = resultObject.projectCount;
            let language          = resultObject.language;
            let availability      = resultObject.availability;
            let bio               = resultObject.bio;
            let pay               = resultObject.pay;

            if(!dropDownListName){ dropDownListName = resultObject.displayName; }
            if(!profession){ profession = ""; }
            if(!memberName){ memberName = ""; }
            if(!emailAddr){ emailAddr = ""; }
            if(!phoneNumber){ phoneNumber = ""; }
            if(!experience){ experience = ""; }
            if(!projectCount){ projectCount = ""; }
            if(!language){ language = ""; }
            if(!availability){ availability = ""; }
            if(!bio){ bio = ""; }
            if(!pay){ pay = ""; }

            let loginWithOAuth = "Server";
            if(resultObject.githubId){
              // console.log(resultObject.githubId);
              loginWithOAuth = "GitHub";
            }
            else if(resultObject.googleId){
              // console.log(resultObject.googleId);
              loginWithOAuth = "Google";
            }

            res.render("settings", {
              userAlreadyExisted: "",
              pageTitle: "Profile Settings",
              username: dropDownListName,
              loggedout: "",
              authorized: req.isAuthenticated(),
  			      loginWith: loginWithOAuth,
              profession: profession,
              memberName: memberName,
              emailAddr: emailAddr,
              phoneNumber: phoneNumber,
              experience: experience,
              projectCount: projectCount,
              language: language,
              availability: availability,
              bio: bio,
              pay: pay
          });
        }
      }
    });
  }
  else{
    res.redirect("/servererror");
  }
}

function renderPrivatePage(req , res, renderMessage){ //renderMessage can be reanderObjects for multi input
  if(mongoose.connection.readyState === 1){
    User.findOne({_id:req.session.passport.user},(err,resultObject)=>{
      if(err){
        console.log(err);
      }
      else{
        if(resultObject){

          ImageModel.findOne({ userID: resultObject._id },(err, resultImage) => {
            if (err) {
              console.log(err);
              res.status(500).send('An error occurred', err);
            }

            if(!resultImage){resultImage = "NOIMAGE";};

            let imageErroMessage = req.body.imageErroMessage;
            if(!imageErroMessage){ imageErroMessage = "";}
            console.log(resultImage);

            let dropDownListName = resultObject.displayName;
            if(!dropDownListName){dropDownListName = resultObject.username; }
            res.render("private", {
              imageErroMessage: renderMessage,
              pageTitle: "Authenticated!",
              username: dropDownListName,
              authorized: req.isAuthenticated(),
              userID: resultObject._id,
              image: resultImage,
              displayName: dropDownListName,
              profession: resultObject.profession,
              memberName: resultObject.memberName,
              emailAddr: resultObject.emailAddr,
              phoneNumber: resultObject.phoneNumber,
              experience: resultObject.experience,
              pay: resultObject.pay,
              projectCount: resultObject.projectCount,
              language: resultObject.language,
              availability: resultObject.availability,
              bio: resultObject.bio,
            }); //render

          }); //Image
        }
      }
    }); //User
  }
  else{
    res.redirect("/servererror");
  }
}

function renderHomePage(req, res){
  if(mongoose.connection.readyState === 1){
    User.findOne({_id:req.session.passport.user},(err,resultObject)=>{
      if(err){
        console.log(err);
      }
      else{
        if(resultObject){
          let dropDownListName = resultObject.username;
          if(!dropDownListName){dropDownListName = resultObject.displayName }
          res.render("home", {
            userAlreadyExisted: "",
            pageTitle: "Mo.Co.",
            username: dropDownListName,
            loggedout: "",
            authorized: req.isAuthenticated()
          });
        }
      }
    });
  }
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
app.post('/private/profileImageUpload', upload.single('image'), (req, res, next) => {

    const imagePath = path.join(__dirname + '/uploads/' + req.file.filename);
    var obj = {
        userID: req.body.userID,
        img: {
            data: fs.readFileSync(imagePath),
            contentType: 'image/png'
        }
    }
    ImageModel.findOneAndUpdate({userID: req.body.userID}, obj, {upsert: true} ,(err, item) => {
        if (err) {
            console.log(err);
            fs.unlinkSync(imagePath);
            res.redirect('/private');
        }
        else {
            console.log("image uploaded.");
            fs.unlinkSync(imagePath);
            res.redirect('/private');
        }
    });
});
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
            if(req.body.remember){
              req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; } // Cookie expires after 30 days
            else { req.session.cookie.expires = false; } // Cookie expires at end of session
            return res.redirect("/private");
          }
        });
      }
    })(req, res, next);
});

app.post("/register", (req, res) => {
  // This function came from passport mongoose
  if(mongoose.connection.readyState === 1){
    User.register({ username: req.body.username }, req.body.password, (err, user) => {
      if (err) {
        console.log(err);
        renderRegisterPage(req, res, "Email already in use.");
      }
      else{
        passport.authenticate("local")(req, res, () => { res.redirect("/private"); });
      }
    });
  }
  else{
    res.redirect("/servererror");
  }
});

app.post("/settings/account", (req, res)=>{
  console.log(req.body);
  let query = { _id: req.session.passport.user};
  let update = { $set: req.body };
  let options = { upsert: true, new: true, setDefaultsOnInsert: true };

  console.log(req.body)
  User.updateOne(query, update, options, (err) => {
     if(err){ console.log(err);}
     else{
       res.redirect("/");
     }
  });
});

app.post("/settings/password", (req, res)=>{
  const currentUser = req.session.passport.user;
  console.log(req.session.passport);
  const oldPassword = req.body.oldPassword;
  const newPassword = req.body.newPassword;
  const confirmPswd = req.body.confirmPswd;
  if(newPassword === confirmPswd){
    if(mongoose.connection.readyState === 1){
      User.findOne({_id:currentUser}, (err, resultObject)=>{
        if(!err){
          if(resultObject){
            resultObject.changePassword(oldPassword, newPassword, (err)=>{
              if(!err){renderLoginPage(req, res, "Password updated, please login again.")}
              else{console.log(err); renderSettingPage(req, res, "Somehting went wrong, please try again...");}
            });
          }
          else{renderSettingPage(req, res, "User does not exist in our record, please signout and try again.");}
        }
        else{ console.log(err); renderSettingPage(req, res, "Somehting went wrong, please try again...");}
      });
    }
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
    renderHomePage(req, res);
  }
  else{
    res.render("home", {
      loggedout: "",
      pageTitle: "Mo.Co.",
      username: "",
      authorized: req.isAuthenticated()
    });
  }
});
//=================================================================|
//                      PROTECTED CONTENT
//-----------------------------------------------------------------|
// "/private" route relies on passport to authenticate
//-----------------------------------------------------------------|
app.get("/private", (req, res) => {
  if (req.isAuthenticated()) {
    renderPrivatePage(req, res, "");
  } else { res.redirect("/login"); }
});

//=================================================================|
//                      SERVER AUTHENICATION
//-----------------------------------------------------------------|
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

//-----------------------------------------------------------------|
//                        GOOGLE OAUTH2.0
//-----------------------------------------------------------------|
// Sign in with Google button take users here
//-----------------------------------------------------------------|
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

// Google OAuth callback
app.get("/auth/google/private",
  passport.authenticate('google', { failureRedirect: "/login"}),
    (req, res) => { res.redirect('/private'); });
    //If OAuth success, bring them to private page.
//-----------------------------------------------------------------|
//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
//-----------------------------------------------------------------|
//                        GITHUT AUTH
//-----------------------------------------------------------------|
// Sign in with GitHub button take users here
//-----------------------------------------------------------------|
app.get("/auth/github",
  passport.authenticate('github', { scope: ["user:email"] })
);

// Github OAuth callback
app.get("/auth/github/private",
  passport.authenticate('github', { failureRedirect: "/login"}),
    (req, res) => { res.redirect('/private'); });
    //If OAuth success, bring them to private page.
//-----------------------------------------------------------------|
//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||

app.get("/logout", (req, res) => {
  //This came from passport
  if(req.session){
    req.logout();
    req.session.destroy();
    res.redirect("/");
  }
});

//=================================================================|
//                        USER SETTINGS
//-----------------------------------------------------------------|
app.get("/settings", (req, res) => {
  if (req.isAuthenticated()) {
    renderSettingPage(req, res, "");
  }
  else { res.redirect("/login"); }
});


//=================================================================|
//                    OTHER SERVER RESPONSE
//-----------------------------------------------------------------|

app.get("/servererror", (req, res) => {
  res.status(500).render("servererror",{
    pageTitle: "5o0 Server Error",
    authorized: req.isAuthenticated()
  });
});

app.get("*", (req, res) => {
  res.status(404).render("notfound",{
    pageTitle: "4o4 NoT FoUnD",
    authorized: req.isAuthenticated()
  });
});

//=================================================================|
//                    SERVER LISTENING PORT
//-----------------------------------------------------------------|
app.listen(process.env.PORT, (err) => {
  console.log("Server is successfully running at prot -: " + process.env.PORT);
});
