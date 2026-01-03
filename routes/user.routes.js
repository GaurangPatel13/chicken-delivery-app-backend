import express from "express";
import { changePassword, getUserProfile, userLogin, userRegister, verifyOtp } from "../controller/user.controller.js";
import userAuth from "../middleware/userAuth.js";
const router = express.Router();
router.post("/register" , userRegister);
router.post("/login" , userLogin);
router.post("/verify-otp" , verifyOtp);
router.get("/profile" , userAuth, getUserProfile);
router.post("/change-password" ,userAuth, changePassword);




export default router;