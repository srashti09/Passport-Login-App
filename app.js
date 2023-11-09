//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyparser = require("body-parser");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
//const md5= require("md5");
//const bcrypt= require("bcrypt");
//const saltRounds=10;
const session =require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy=require("passport-google-oauth20").Strategy;
const findOrCreate=require("mongoose-findorcreate");



//const SECRET=(process.env.SECRET);

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyparser.urlencoded(
    {
        extended:true
    }
));
app.use(session(
    {
        secret:"our little secret",
        resave:false,
        saveUninitialized:false
    }));
    
app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true});

//mongoose.set("useCreateIndex",true);

const userSchema = mongoose.Schema({
    email: String,
    password :String,
    googleId:String,
    secret:String,
    secrets: [String],
    
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt,{secret:SECRET, encryptedFields :["password"]});
const User = new mongoose.model("User",userSchema)
// left User ==>model variable
//right User ==>model name

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id)
        .then(user => {
            done(null, user);
        })
        .catch(err => {
            done(err, null);
        });
});



passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:4000/auth/google/secrets",
    //userProfileURL: "https://www.google.apis.com/oauth2/v3/userinfo"

  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        console.log(profile);
      return cb(err, user);
    });//findorcreate is used to find in our dbase and if not existed create the memory for this email 
  }
));

app.get("/",function(req,resp)
{
    resp.render("home")
})
app.get("/auth/google",passport.authenticate('google', { scope: ["profile"] }));

app.get("/auth/google/secrets",passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login",function(req,resp)
{
    resp.render("login")
})
app.get("/register",function(req,resp)
{
    resp.render("register");
})
app.get("/secrets", async function(req, res) {
    try {
        if (req.isAuthenticated()) {
            const userId = req.user._id;
            const foundUser = await User.findById(userId);

            if (foundUser) {
                const userSecrets = foundUser.secrets;
                console.log(foundUser.secrets); 
                res.render("secrets", { usersWithSecrets: userSecrets });
                //console.log(usersWithSecrets.secrets);
            } else {
                console.log("User not found.");
            }
        } else {
            res.redirect("/login");
        }
    } catch (err) {
        console.error(err);
        // Handle any errors that might occur during the operation
    }
});

  
app.get("/submit",function(req,res)
{
    if(req.isAuthenticated())
    {
        res.render("submit");
    }
    else{
        res.redirect("/login")
    }
});
app.post("/submit", async function(req,res)
{
    try
    {

    const submittedsecret = req.body.secret;
    const foundUser =await User.findById(req.user.id);
        
    if (foundUser) {
        foundUser.secrets.push(submittedsecret); // Add the new secret to the array
        
                await foundUser.save();
                res.redirect("/secrets")
                
            }
        }

    catch(err)
    {
        console.log(err)

    }
});
app.get("/logout",function(req,res)
{
    req.logout(function()
    {

       res.redirect("/")
    });  
});





// TO SEND DATA TO DBASE
app.post("/register", async function(req,res)
 {
        /*bcrypt.hash(req.body.password,saltRounds, async function(err,hash)
    {
    const newUser = new User({
        email: req.body.username,
        password: hash
        
    });
    console.log(newUser);

    try {
        await newUser.save();
        res.render("secrets");
    } 
    catch (err) {
        console.log(err);
        // Optionally, you can send a response back to the user in case of an error

        //res.status(500).send("Server Error");
    }
});*/
  User.register(
    {
        username:req.body.username} , req.body.password,  await function (err, user)  
        {
            if (err) 
            {
                console.error(err);
                // Handle registration failure (e.g., display an error message)
                res.redirect('/register');
            } else 
            {
                // Registration successful, you can redirect to a different page
                //res.redirect('/login');
                passport.authenticate("local")(req,res,function()
                {
                    res.redirect("/secrets");
                })
            }
        } 

    
)
});

app.post("/login", async function(req, res) {
    const user=new User(
        {
            username:req.body.username,
            password:req.body.password
        }
    );
    req.login(user,function(err)
    {
        if(err)
        console.log(err);
        else
        {
            passport.authenticate("local")(req,res,function()
            {

                res.redirect("/secrets");
            });    
        }
    });









    /*const username = req.body.username;
    const password = req.body.password;
    console.log(password);

    //try {
        const foundUser = await User.findOne({ email: username });

        if (foundUser) 
        {
            bcrypt.compare(password,foundUser.password,function(err,result)
            {
                if(result===true)
                res.render("secrets");
            })
            
        }    */
            
            /*if (foundUser.password === password) {
                
            } 
        else 
        {
                console.log("Password does not match.");
                // You can also send a response here to inform the user
        }*/
            /*
        } else {
            console.log("No user found with that email.");
            // You can also send a response here to inform the user
        }
    } catch (err) {
        console.log(err);
        // You can also send a response here to inform the user of a server error*/
    }

);




app.get("/secrets",function(req,resp)
{
    resp.render("secrets")
})
app.get("/submit",function(req,resp)
{
    resp.render("submit")
})



app.listen(4000,function()
    {
        console.log("server  started at port 4000")
    }
);
