import express from "express";
import { PORT, SECRET_KEY_JWT } from "./config.js";
import { UserRepository } from "./use-repository.js";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

//Authentication
app.use(async (req, res, next) => {
  function extractUserId(token) {
    try {
      const decoded = jwt.decode(token); // Decode without verification
      return decoded ? decoded.userId : null;
    } catch (err) {
      return null;
    }
  }
  const token = req.cookies.access_token;
  const user_id = extractUserId(token);
  let user_secret;
  try {
    user_secret = await UserRepository.getUserSecret({ user_id });
  } catch (error) {}
  const signInKey = `${SECRET_KEY_JWT}.${user_secret}`;
  req.session = { user: null };
  try {
    const data = jwt.verify(token, signInKey);
    req.session.user = data;
  } catch {}
  next();
});

app.get("/", (req, res) => {
  res.send("Api running");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log(username);
  console.log(password);
  try {
    const user = await UserRepository.login({ username, password });
    const signInKey = `${SECRET_KEY_JWT}.${user.user_secret}`;
    const { user_secret, ...publicUser } = user;
    const token = jwt.sign(
      { username: user.username, _id: user._id },
      signInKey,
      { expiresIn: "1h" }
    );
    res
      .cookie("access_token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
      })
      .send({ publicUser });
  } catch (error) {
    res.status(401).send(error.message);
  }
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const id = await UserRepository.create({ username, password });
    res.send(id);
  } catch (error) {
    res.send(error.message);
  }
});
app.post("/logout", (req, res) => {
  res.clearCookie("access_token");
  res.status(200).send("Logged out successfully");
});

app.get("/protected", (req, res) => {
  const user = req.session.user;
  res.render("protected", { username: user.username });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
