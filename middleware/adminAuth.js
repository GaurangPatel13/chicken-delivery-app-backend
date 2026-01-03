import jwt from "jsonwebtoken"
import Admin from "../models/admin.model.js";


const adminAuth = async (req, res, next) => {
  const authHeader = req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return res.status(401).json({ success: false, message: "No token provided" });
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) return res.status(401).json({ success: false, message: "Invalid or expired token" });
    if (decoded.role !== "admin") return res.status(401).json({ success: false, message: "Unauthorized access" });
    const admin = await Admin.findById(decoded._id).select("-password");
    if (!admin) return res.status(401).json({ success: false, message: "Admin not found" });
    if (admin.isBlocked) return res.status(401).json({ success: false, message: `${admin.role} has been blocked. Please contact Admin` });
    if (!["admin",'manager','staff','super-admin'].includes(admin.role)) return res.status(401).json({ success: false, message: `Invaild Employ type` });
    req.admin = admin;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: error.message });
  }
};

export default adminAuth;
