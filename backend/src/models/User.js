import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  hashPassword: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    repuired: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  displayName: {
    type: String,
    required: true,
    trim: true,
  },
  avatarUrl: {
    type: String,
  },
  avatarId: {
    type: String,
  },
  bio: {
    type: String,
    maxlegth: 500,
  },
  phone: {
    type: String,
    sparse: true,
  },
  timedstamp: true,
});
const User = mongoose.model("User", userSchema);
export default User;
