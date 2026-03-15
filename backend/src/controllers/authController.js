import bcrypt from "bcrypt";
import User from "../models/User";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const ACCESS_TOKEN_TTL = "30m"; //hoac 15m
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; //14 ngay

export const signUp = async (req, res) => {
  try {
    const { username, password, email, firstName, lastName } = req.body;

    if (!username || !password || !email || !firstName || !lastName) {
      return res.status(400).json({ message: "All fields are required" });
    }
    // kiem tra username da ton tai chua
    const duplicate = await User.findOne({ username });
    if (duplicate) {
      return res.status(409).json({ message: "Username already exists" });
    }
    // ma hoa password
    const hashPassword = await bcrypt.hash(password, 10);
    // tao user moi
    await User.create({
      username,
      hashPassword,
      email,
      displayName: `${firstName} ${lastName}`,
    });
    return res.status(204);
  } catch (error) {
    console.error("Error in signUp:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
export const signIn = async (req, res) => {
  try {
    // lay input
    const { username, password } = req.body;
    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username and password are required" });
    }
    // lay hashPassword tu db de so sanh voi password nguoi dung nhap vao
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }
    // kiem tra password
    const passwordCorrect = await bcrypt.compare(password, user.hashPassword);
    if (!passwordCorrect) {
      return res.status(401).json({ message: "Invalid username or password" });
    }
    // neu khop, tao accessToken voi JWT
    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: ACCESS_TOKEN_TTL }
    );
    // tao refreshToken
    const refreshToken = crypto.randomBytes(64).toString("hex");
    // tao session moi de luu refreshtoken
    await Session.create({
      userId: user._id,
      refreshToken,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
    });
    // tra refreshToken ve trong cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "none",
      maxAge: REFRESH_TOKEN_TTL,
    });
    // tra accessToken ve trong res
    return res.status(200).json({
      message: "User ${user.displayName} signed in successfully",
      accessToken,
    });
  } catch (error) {
    console.error("Error in signIn:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
export const signOut = async (req, res) => {
  try {
    // lay refresh token tu cookie
    const token = req.cookies?.refreshToken;

    if (token) {
      // xoa session trong session
      await Session.deleteOne({ refreshToken: token });

      // xoa cookie
      res.clearCookie("refreshToken");
    }

    return res.sendStatus(204);
  } catch (error) {
    console.error("Error in signOut:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
