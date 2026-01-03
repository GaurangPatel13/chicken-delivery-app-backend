import jwt from "jsonwebtoken";
import DeliveryBoy from "../models/deliveryBoy.model.js";

const deliveryAuth = async (req, res, next) => {
  try {
    const authHeader = req.header("Authorization");

    if (!authHeader?.startsWith("Bearer "))
      return res
        .status(401)
        .json({ success: false, message: "Authorization token missing." });

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await DeliveryBoy.findById(decoded.id).select("-password");

    if (!user)
      return res
        .status(401)
        .json({ success: false, message: "User not found." });

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

export default deliveryAuth;
