const express = require("express");
const app = express();
const dotenv = require("dotenv");
const mongoose = require("mongoose");

// Import routes
const authRoute = require("./routes/auth");
const postRoute = require("./routes/post");

dotenv.config();

// Connect to DB
mongoose.connect(
  process.env.DB_CONNECT,
  { useNewUrlParser: true, useUnifiedTopology: true },
  () => {
    console.log("Connected to db!");
  }
);

// Middleware
app.use(express.json());

// Route Middileware
app.use("/api/user", authRoute);
app.use("/api/post", postRoute);

// Server listen
app.listen(3000, () => console.log("Server Up and runing"));
