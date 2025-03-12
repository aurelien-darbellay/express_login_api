import DBLocal from "db-local";
import bcrypt from "bcrypt";
import { SALT_ROUNDS } from "./config.js";
import crypto from 'crypto'

const { Schema } = new DBLocal({ path: "./db" });

const User = Schema("User", {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  user_secret:{type:String, required: true}
});

function generateUserSecretKey() {
  return crypto.randomBytes(32).toString('hex'); // Generates a unique 256-bit key
}
export class UserRepository {
 
  static async create({ username, password }) {
    Validation.username(username);
    Validation.username(password);
    const user = User.findOne({ username });
    if (user) throw new Error("username already exists");
    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password,SALT_ROUNDS);
    const user_secret = generateUserSecretKey();
    User.create({
      _id: id,
      username,
      password: hashedPassword,
      user_secret
    }).save();
    return id;
  }

  static async login({ username, password }) {
    Validation.username(username);
    Validation.password(password);
    const user = User.findOne({ username });
    if(!user) throw new Error("Username doesn't exist");
    const isValid = await bcrypt.compare(password,user.password);
    if (!isValid) throw new Error("Wrong password");

    const {password:_, ...publicUser} = user;
    return publicUser;
  }

  static async getUserSecret({_id}){
    const user = User.findOne({_id});
    if(!user) throw new Error("User doesn't exist");
    return user.user_secret;
  }
}

class Validation {
  static username(username){
    if (typeof username != "string")
      throw new Error("username must be a string");
    if (username.length < 3) throw new Error("username too short");
  }
  static password(password){
    if (typeof password != "string")
      throw new Error("password must be a string");
    if (password.length < 6) throw new Error("password too short");
  }
}
