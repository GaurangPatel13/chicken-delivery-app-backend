import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

const userAuth = async (req, res, next) => {
  const authHeader = req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer"))
    return res.status(401).json({ message: "Authorization token missing." });
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    let user = await User.findById(decoded.id).select("-password");
    // if (!user.isVerified) return res.status(403).json({ success: false, message: "User not verified." });
    if (user.isBlock)
      return res
        .status(403)
        .json({ success: false, message: "User is blocked." });
    req.user = user;
    next();
  } catch (err) {
    console.log(err);
    return res
      .status(401)
      .json({ success: false, message: "Invalid or expired token." });
  }
};

export default userAuth;
