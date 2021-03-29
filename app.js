
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
const multer = require('multer'); //for image uploading use.
const FacebookStrategy = require("passport-facebook").Strategy;
const GoogleStrategy  = require("passport-google-oauth20").Strategy; // Google OAuth20
const GitHubStrategy = require("passport-github2").Strategy; // passport-github2;
const HttpsProxyAgent = require('https-proxy-agent'); //proxy... just need to do this anyway..

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

//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                  MONGOOSE DATABASE CONNECTION
//-----------------------------------------------------------------|
// Some day in the future I will be dealing with this cloud server env variables...
//reference: https://devcenter.heroku.com/articles/config-vars
let devMongoDBURI="mongodb://" + process.env.DB_HOST + ":" + process.env.DB_PORT + "/" + process.env.DB_NAME;
let prdMongoDBURI="mongodb+srv://" + process.env.DB_USER + ":" + process.env.DB_PSWD + "@cluster0.gugxn.mongodb.net/" + process.env.DB_NAME;

if(process.env.SERVER_URI != "http://localhost:3000"){
  console.log("Starting up with PRD mongoDB connection.");
  mongoose.connect(prdMongoDBURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
} else {
  console.log("Starting up with DEV mongoDB connection.");
  mongoose.connect(devMongoDBURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
}

// need to use createIndex and useFindAndModify otherwise its depreated
//-----------------------------------------------------------------|
mongoose.set('useCreateIndex', true);
mongoose.set('useFindAndModify', false);

//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                   MONGOOSE DATABASE SCHEMA
//-----------------------------------------------------------------|
const userSchema = mongoose.Schema({
  username: String,
  password: String,
  googleId : String,
  githubId : String,
  facebookId: String,
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
  img:{
    data: Buffer,
    contentType: String
  },
  userID: String,
  name: String,
});

const serviceSchema = new mongoose.Schema({
  img:{
    data: Buffer,
    contentType: String
  },
  serviceTitle: String,
  serviceDetails: String,
  createDate: Date,
  userID: String,
  pay: String,
});

// add plugin for mongoose userPassword schema.
// add plugin for findOrCreate package
//-----------------------------------------------------------------|
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                   MONGOOSE DOCUMENT MODEL
//-----------------------------------------------------------------|
// User database mongoDB mongoose model
//-----------------------------------------------------------------|
const User = mongoose.model("User", userSchema);
const Service = mongoose.model("Service", serviceSchema);
const ImageModel = new mongoose.model('Image', imageSchema);

//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                      IMAGE UPLOAD STORAGE
//-----------------------------------------------------------------|
let imageDir = path.join(__dirname + "/uploads/");
console.log("Checking image directory ...")
if (!fs.existsSync(imageDir)){
  console.log("Creating image directory -: " + imageDir);
  fs.mkdirSync(imageDir);
  console.log("Image upload directory created. -: " + imageDir);
}
else{
  console.log("Checking image directory existed -: " + imageDir);
}

let storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "uploads");
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now());
    }
});

let upload = multer({ storage: storage });

//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
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
    callbackURL: process.env.SERVER_URI + "/auth/google/private",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  (accessToken, refreshToken, profile, done) => {
    // console.log(profile); // create user profile id from this callback function from passport google OAuth 2.
    User.findOrCreate({ googleId: profile.id, displayName: profile.displayName}, (err, user) => {
      if (err) { return done(err); }
      return done(err, user);
    });
  }
)

// Using Passport Github Open Authentication 2.0
//-----------------------------------------------------------------|
const githubOAuth20Strategy = new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.SERVER_URI + "/auth/github/private",
  },
  (accessToken, refreshToken, profile, done) => {
    // console.log(profile);
    User.findOrCreate({ githubId: profile.id, displayName: profile.displayName,  username:profile.username }, (err, user) => {
      if (err) { return done(err); }
      return done(err, user);
    });
  }
)

// Using Passport Facebook Open Authentication
//-----------------------------------------------------------------|
const facebookOAuthStrategy =  new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.SERVER_URI + "/auth/facebook/private",
  },
  (accessToken, refreshToken, profile, done) => {
    // console.log(profile);
    // console.log(profile.id);
    // console.log(profile.displayName);
    User.findOrCreate({ facebookId: profile.id, displayName: profile.displayName,  username:profile.username }, (err, user) => {
      if (err) { return done(err); }
      done(null, user);
    });
  }
)

//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                     PROXY SETTINGS
//-----------------------------------------------------------------|
// Set Google OAuth to use proxy agent HTTP_PROXY=http://<proxyUser>:<proxyPass>@<proxyURL>:<proxyPort>
// Comment this out if no proxy needed.
// reference: https://github.com/drudge/passport-facebook-token/issues/67
// restart application server to apply proxy change
//-----------------------------------------------------------------|
const proxyAgent = new HttpsProxyAgent(process.env.HTTP_PROXY);

// Set proxy agent to OAuth Strategies
//-----------------------------------------------------------------|
// googleOAuth20Strategy._oauth2.setAgent(proxyAgent);
// githubOAuth20Strategy._oauth2.setAgent(proxyAgent);
// facebookOAuthStrategy._oauth2.setAgent(proxyAgent);

// Set Passport to use Strategies
//-----------------------------------------------------------------|
passport.use(googleOAuth20Strategy);
passport.use(githubOAuth20Strategy);
passport.use(facebookOAuthStrategy);

// For proxy setting
//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                  DEMO PAGE RENDERER FUNCTIONS
//-----------------------------------------------------------------|
function renderSettingPage(req, res, renderMessage){
  if(mongoose.connection.readyState === 1){ // 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting
    User.findOne({_id:req.session.passport.user},(err,resultObject)=>{
      if(err){
        console.log(err);
      }
      else{
        if(resultObject){
            let dropDownListName  = resultObject.displayName;
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

            if(!dropDownListName){dropDownListName = resultObject.username; }
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
            else if(resultObject.facebookId){
              // console.log(resultObject.facebookId);
              loginWithOAuth = "Facebook";
            }

            console.log(renderMessage);
            res.status(200).render("settings", {
              userAlreadyExisted: renderMessage,
              pageTitle: "Profile Settings",
              username: dropDownListName,
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
    res.status(500).redirect("/servererror");
  }
}

function renderProfilePage(ejs, req , res, userName){
  if(mongoose.connection.readyState === 1){
    User.findOne({_id: req.params.userID},(err,resultUserObject)=>{
      if(err){
        console.log(err);
      }
      else{
        if(resultUserObject){

          ImageModel.findOne({ userID: req.params.userID },(err, resultImage) => {
            if (err) {
              console.log(err);
              res.status(500).send('An error occurred', err);
            }

            Service.find({ userID: req.params.userID},(err, resultService) => {
              if (err) {
                console.log(err);
                res.status(500).send('An error occurred', err);
              }

              if(!resultImage){resultImage = "NOIMAGE";};

              let imageErroMessage = req.body.imageErroMessage;
              if(!imageErroMessage){ imageErroMessage = "";}
              //console.log(resultImage);

              let dropDownListName = resultUserObject.displayName;
              if(!dropDownListName){dropDownListName = resultUserObject.username; }

              console.log(req.session);
              res.status(200).render(ejs, {
                pageTitle: dropDownListName,
                username: userName, // this is the username for header for current user.
                authorized: req.isAuthenticated(),
                image: resultImage,
                displayName: dropDownListName,
                userRelated: resultUserObject,
                serviceCount: resultService.length
              }); //service
            }); //render
          }); //Image
        }
      }
    }); //User
  }
  else{
    res.status(500).redirect("/servererror");
  }
}

function renderPrivatePage(ejs, req , res, renderMessage){ //renderMessage can be reanderObjects for multi input
  if(mongoose.connection.readyState === 1){
    User.findOne({_id:req.session.passport.user},(err,resultUserObject)=>{
      if(err){
        console.log(err);
      }
      else{
        if(resultUserObject){

          ImageModel.findOne({ userID: resultUserObject._id },(err, resultImage) => {
            if (err) {
              console.log(err);
              res.status(500).send('An error occurred', err);
            }

            Service.find({ userID: resultUserObject._id },(err, resultService) => {
              if (err) {
                console.log(err);
                res.status(500).send('An error occurred', err);
              }

              if(!resultImage){resultImage = "NOIMAGE";};

              let imageErroMessage = req.body.imageErroMessage;
              if(!imageErroMessage){ imageErroMessage = "";}
              //console.log(resultImage);

              let dropDownListName = resultUserObject.displayName;
              if(!dropDownListName){dropDownListName = resultUserObject.username; }
              res.status(200).render(ejs, {
                imageErroMessage: renderMessage,
                pageTitle: dropDownListName,
                username: dropDownListName,
                authorized: req.isAuthenticated(),
                image: resultImage,
                displayName: dropDownListName,
                userRelated: resultUserObject,
                serviceCount: resultService.length
              }); //service
            }); //render
          }); //Image
        }
      }
    }); //User
  }
  else{
    res.status(500).redirect("/servererror");
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
          let dropDownListName = resultObject.displayName;
          if(!dropDownListName){dropDownListName = resultObject.username; }
          res.status(200).render("home", {
            userAlreadyExisted: "",
            pageTitle: "Mo.Co.",
            username: dropDownListName,
            authorized: req.isAuthenticated()
          });//render
        }
      }
    });//User
  }
}

function renderAcitvePosting_sub(ejs, res, username, resultobjList, isAuth){
  res.status(200).render(ejs, {
    pageTitle: "Posting",
    username: username,
    listofService: resultobjList,
    authorized: isAuth
  }); //render
}

function renderActivePostingPage(ejs, req, res, query){
  if(mongoose.connection.readyState === 1){
    if(req.isAuthenticated()) {
      const currentUser = req.session.passport.user;
      User.findOne({ _id: currentUser}, (err, resultObject) => {
        if(err){ console.log(err); }
        else{
          let dropDownListName = resultObject.displayName;
          if(!dropDownListName){dropDownListName = resultObject.username; }
          // only shows service name, and service detial,
          // make some interface to show provider details.
          //Call back hell reference: https://medium.com/codebuddies/getting-to-know-asynchronous-javascript-callbacks-promises-and-async-await-17e0673281ee
          Service.find(query,(err, resultObjectList) => {
            // console.log("at -:" + ejs + " return results -:");
            // console.log(resultObjectList);
            renderAcitvePosting_sub(ejs, res, dropDownListName, resultObjectList, req.isAuthenticated());
          }); //service
        }
      }); //user
    }
    else{
      Service.find(query,(err, resultObjectList) => {
        renderAcitvePosting_sub(ejs, res, "", resultObjectList, req.isAuthenticated());
      }); //service
    }
  }
}

function renderLoginPage(req, res, renderMessage){
  res.status(200).render("login", {
    userAlreadyExisted: renderMessage,
    pageTitle: "Login Page",
    username: "",
    authorized: req.isAuthenticated()
  });
}

function renderRegisterPage(req, res, renderMessage){
  res.status(200).render("register", {
    userAlreadyExisted: renderMessage,
    pageTitle: "Registration",
    username: "",
    authorized: req.isAuthenticated()
  });
}

function render404NotFoundPage(res, req, username){
  res.status(404).render("notfound",{
    pageTitle: "4o4 NoT FoUnD",
    username: username,
    authorized: req.isAuthenticated()
  });
}
//=================================================================|
//                      DEMO SITE POST ROUTE
//-----------------------------------------------------------------|
//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                        USER SPECIFIC
//-----------------------------------------------------------------|
app.post("/private/serviceUnlisting", (req, res) => {
  //console.log(req.body.userID);
  console.log(typeof(req.body.unlistServiceID));
  let query = { _id: req.body.unlistServiceID };
  Service.deleteOne( query , (err) => {
    if(err){ console.log(err); }
    else{

      console.log("Post (" + req.body.unlistServiceID + ") deleted.");
      res.status(200).redirect("/myposts");
    }
  }); //service
});

app.post("/private/servicePosting", (req, res) => {
    //console.log(req.body);

    User.findOne({ _id: req.body.userID }, (err, resultUserObject) => {
      if(err) { console.log(err); }
      else{

        ImageModel.findOne({ userID: resultUserObject._id }, (err, resultImageObject) => {
          if(err) { console.log(err); }
          else{

            let postImage = {};
            if(resultImageObject){
              postImage = resultImageObject.img;
            }

            //console.log(resultImageObject);
            let newService = new Service({
              img: postImage,
              serviceTitle:req.body.serviceTitle,
              serviceDetails:req.body.serviceDetails,
              createDate: Date.now(),
              userID: resultUserObject._id,
              pay: resultUserObject.pay
            });//ImageModel

            console.log(newService);
            Service.create(newService ,(err, item) => {
                if (err) { console.log(err); }
                else {
                    //show something to user that the service is posted.
                    console.log("Service posted -: " + req.body.userID);
                    res.status(200).redirect('/myposts');
                }
              });//Service
          }
        }); //imageModel
      }
    });//User
});

app.post("/private/profileImageUpload", upload.single('image'), (req, res, next) => {
  console.log("REMINDER: do somthing for image resizing...");
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
          res.status(200).redirect('/private');
      }
      else {

          console.log("image uploaded.");
          Service.updateMany({ userID: req.body.userID }, obj, {upsert: false}, (err) => {
            if(err){ console.log(err);}
            else{
              fs.unlinkSync(imagePath);
              res.status(200).redirect('/private');
              console.log("image at service posting updated.");
            }
          }); //Service
      }
    }); //ImageModel
});

app.post("/settings/account", (req, res)=>{
  //console.log(req.body);
  let query = { _id: req.session.passport.user};
  let update = { $set: req.body };
  let options = { upsert: true, new: true, setDefaultsOnInsert: true };

  //console.log(req.body)
  User.updateOne(query, update, options, (err) => {
     if(err){ console.log(err);}
     else{

       Service.updateMany({ userID: req.session.passport.user }, update, { upsert: false } , (err) => {
         if(err){ console.log(err);}
         else{
            res.status(200).redirect("/private");
         }
       }); //Service
     }
  }); //User
});

app.post("/settings-password", (req, res)=>{
  const currentUser = req.session.passport.user;
  console.log(req.session.passport);
  const oldPassword = req.body.oldPassword;
  const newPassword = req.body.newPassword;
  const confirmPswd = req.body.confirmPswd;
  if(newPassword === confirmPswd){
    if(mongoose.connection.readyState === 1){
      User.findOne({_id:currentUser}, (err, resultObject)=>{
        if(err){
          console.log(err);
          renderSettingPage(req, res, "Somehting went wrong, please try again...");
          }
          if(resultObject){
            resultObject.changePassword(oldPassword, newPassword, (err)=>{
              if(err){
                console.log(err);
                renderSettingPage(req, res, "Password does not match our records, please try again...");
              }
              else{renderLoginPage(req, res, "Password updated, please login again."); }
            });
          } else{renderSettingPage(req, res, "User does not exist in our record, please signout and try again."); }
      }); //User
    }
  }
  else{ renderSettingPage(req, res, "Both columns of new password must be the same."); }
});

//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                      SERVER AUTHENICATION
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
            if(req.body.remember){
              req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; } // Cookie expires after 30 days
            else { req.session.cookie.expires = false; } // Cookie expires at end of session
            return res.status(200).redirect("/private");
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
        passport.authenticate("local")(req, res, () => { res.status(200).redirect("/private"); });
      }
    });
  }
  else{
    res.status(500).redirect("/servererror");
  }
});
//=================================================================|
//                      DEMO SITE GET ROUTE
//-----------------------------------------------------------------|
//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                      ENTERY POINT
//-----------------------------------------------------------------|
app.get("/", (req, res) => {
  res.status(200).redirect("/home");
});

app.get("/home", (req, res) => {
  if (req.isAuthenticated()) {
    renderHomePage(req, res);
  }
  else{
    res.status(200).render("home", {
      pageTitle: "Mo.Co.",
      username: "",
      authorized: req.isAuthenticated()
    });
  }
});
//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                      SERVER AUTHENICATION
//-----------------------------------------------------------------|
app.get("/register", (req, res) => {
  if (req.isAuthenticated()) { res.status(200).redirect("/private"); }
  else {renderRegisterPage(req, res, ""); }
});

app.get("/login", (req, res) => {
  if (req.isAuthenticated()) { res.status(200).redirect("/private"); }
  else {renderLoginPage(req, res, ""); }
});

app.get("/logout", (req, res) => {
  //This came from passport
  if(req.session){
    req.logout();
    req.session.destroy();
    res.redirect("/login");
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
    (req, res) => { res.status(200).redirect('/private'); });
    //If OAuth success, bring them to private page.

//-----------------------------------------------------------------|
//                        GITHUT OAUTH
//-----------------------------------------------------------------|
// Sign in with GitHub button take users here
//-----------------------------------------------------------------|
app.get("/auth/github",
  passport.authenticate('github', { scope: ["user:email"] })
);

// Github OAuth callback
app.get("/auth/github/private",
  passport.authenticate('github', { failureRedirect: "/login"}),
    (req, res) => { res.status(200).redirect('/private'); });
    //If OAuth success, bring them to private page.

//-----------------------------------------------------------------|
//                      FACEBOOK OAUTH
//-----------------------------------------------------------------|
// Sign in with GitHub button take users here
//-----------------------------------------------------------------|
app.get("/auth/facebook",
  passport.authenticate("facebook")
);

// Github OAuth callback
app.get("/auth/facebook/private",
  passport.authenticate("facebook", { failureRedirect: "/login"}),
    (req, res) => { res.status(200).redirect('/private'); });
    //If OAuth success, bring them to private page.

//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                        USER SPECIFIC
//-----------------------------------------------------------------|
// "/private" route relies on passport to authenticate
//-----------------------------------------------------------------|
app.get("/listService", (req, res) => {
  if (req.isAuthenticated()) {
    renderPrivatePage("listService", req , res, "")
  } else { res.status(200).redirect("/login"); }
});

app.get("/private", (req, res) => {
  if (req.isAuthenticated()) {
    renderPrivatePage("private",req, res, "");
  } else { res.status(200).redirect("/login"); }
});

app.get("/profile/:userID", (req, res) => {
  if (req.isAuthenticated()) {
    User.findOne({ _id: req.session.passport.user}, (err, resultUser) => {
      console.log(resultUser.username)
      renderProfilePage("profile",req, res, resultUser.username);
    });
  } else{
    renderProfilePage("profile",req, res, "");
  }
});

app.get("/settings", (req, res) => {
  if (!req.isAuthenticated()) { res.status(200).redirect("/login"); }
  renderSettingPage(req, res, "");

});

app.get("/activeposting", (req, res) => {
  let query = {};
  renderActivePostingPage("activeposting", req, res, query);
});


app.get("/myposts", (req, res) => {
  if (!req.isAuthenticated()) { res.status(200).redirect("/login"); }

  const currentUser = req.session.passport.user;
  let query = { userID: currentUser };
  renderActivePostingPage("myposts", req, res, query);

});

app.get("/activeposting/:serviceID", (req, res) => {
  let query = { _id: req.params.serviceID };
  renderActivePostingPage("post", req, res, query);
});

//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
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
  if (!req.isAuthenticated()) {
    render404NotFoundPage(res, req, "");
  }
  else{
    if(mongoose.connection.readyState === 1){
      const currentUser = req.session.passport.user;
      User.findOne({ _id: currentUser}, (err, resultObject) => {
        if(err){ console.log(err); }
        else{
          let dropDownListName = resultObject.displayName;
          if(!dropDownListName){dropDownListName = resultObject.username; }
            render404NotFoundPage(res, req, dropDownListName)
          }
        });
      }
    }
});
//-----------------------------------------------------------------|
////////////////////////////////////////////////////////////////////
//=================================================================|
//                    SERVER LISTENING PORT
//-----------------------------------------------------------------|
app.listen(process.env.PORT, (err) => {
  console.log("Server is successfully running at prot -: " + process.env.PORT);
});
