import express from "express";
import { changePassword, forgotPassword, getUserProfile, resendOtp, resetPassword, userLogin, userRegister, verifyOtp } from "../controller/user.controller.js";
import userAuth from "../middleware/userAuth.js";
const router = express.Router();
router.post("/register" , userRegister);
router.post("/login" , userLogin);
router.post("/verify-otp" , verifyOtp);
router.get("/profile" , userAuth, getUserProfile);
router.post("/change-password" ,userAuth, changePassword);
router.post("/resend-otp" , resendOtp);
router.post("/forgot-password" , forgotPassword);
router.post("/reset-password", resetPassword);




export default router;