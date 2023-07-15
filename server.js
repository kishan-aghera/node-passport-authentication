import express from "express";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import { initialize } from "./passport-config.js";
import flash from "express-flash";
import dotenv from "dotenv";
import methodOverride from "method-override";

const app = express();
dotenv.config();

app.set("view-engine", "ejs");
app.use(express.urlencoded({extended: false}));
app.use(flash());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));

const users = [];

const checkAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

const checkNotAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}

app.get("/", checkAuthenticated, (req, res) => {
  res.render("index.ejs", {
    name: req.user.name
  });
});

app.get("/login", checkNotAuthenticated, (req, res) => {
  res.render("login.ejs", {
    name: "Kishan"
  });
});

app.post("/login", checkNotAuthenticated, passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login",
  failureFlash: true
}));

app.get("/register", checkNotAuthenticated, (req, res) => {
  res.render("register.ejs", {
    name: "Kishan"
  });
});

app.post("/register", checkNotAuthenticated, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    users.push({
      id: Date.now().toString(),
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword
    })
    res.redirect("/login");
  } catch {
    res.redirect("/register")
  }
  console.log(users);
});

app.delete('/logout', (req, res, next) => {
  req.logOut((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/login');
  });
});

initialize(passport,
  (email) => users.find(user => user.email === email),
  id => users.find(user => user.id === id)
);

app.listen(3000);
