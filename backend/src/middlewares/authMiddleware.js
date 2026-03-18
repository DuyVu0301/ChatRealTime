import jwt from "jsonwebtoken";
import User from "../models/User.js";

export const protectedRoute = (req, res, next) => {
  try {
    // lay token tu header
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "Can't found Accesstoken." });
    }

    // xac nhan token khong hop le
    jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET,
      async (err, decodedUser) => {
        if (err) {
          console.error(err);

          return res
            .status(403)
            .json({ message: "Access token has expired or is incorrect." });
        }

        // tim user
        const user = await User.findById(decodedUser.userId).select(
          "-hashedPassword"
        );

        if (!user) {
          return res.status(404).json({ message: "User doesn't exist." });
        }

        // tra user ve trong req
        req.user = user;
        next();
      }
    );
  } catch (error) {
    console.error("JWT authentication error in AuthMiddleware", error);
    return res.status(500).json({ message: "Error" });
  }
};
