import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { sendToOtp } from "../utils/nodemailer.js";
import { validatePassword } from "../utils/helperFunctions.js";

export const userRegister = async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;

    if (!name || !email || !mobile || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const userExists = await User.findOne({
      $or: [{ email }, { mobile }],
    });
    console.log(userExists, "userExist");
    if (userExists) {
      if (!userExists.isVerified) {
        userExists.name = name;

        const getHashPassword = await bcrypt.compare(
          password,
          userExists.password
        );
        userExists.password = getHashPassword;

        const otp = Math.floor(100000 + Math.random() * 900000);

        await sendToOtp({
          user: userExists,
          otp,
        });

        return res.status(200).json({
          success: true,
          message: "Account not verified. Verification email sent successfully",
        });
      }
      return res.status(400).json({ message: "User already exists" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);

    const passwordHash = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      mobile,
      password: passwordHash,
      otp,
      otpExpire: Date.now() + 10 * 60 * 1000, // 10 mins
    });

    await newUser.save();

    await sendToOtp({
      user: newUser,
      otp,
    });

    return res
      .status(201)
      .json({ message: "User registered successfully. OTP sent to email", success: true });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error in user registration", error: error.message });
  }
};

export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: "Email & OTP are required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check OTP match
    if (user.otp !== Number(otp)) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // Check expiry
    if (user.otpExpire < Date.now()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    // Mark verified
    user.isVerified = true;
    user.otp = null;
    user.otpExpire = null;
    await user.save();

    // Create token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    return res.status(200).json({
      message: "OTP verified successfully",
      success: true,
      token,
      user: {
        name: user.name,
        email: user.email,
        mobile: user.mobile,
      },
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Server error", error: error.message });
  }
};

export const userLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email & Password are required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    if (!user.isVerified) {
      return res.status(403).json({ message: "User not verified" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    return res.status(200).json({
      message: "Login successful",
      success: true,
      token,
      user: {
        name: user.name,
        email: user.email,
        mobile: user.mobile,
      },
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Server error", error: error.message });
  }
};

export const getUserProfile = async (req, res) => {
  try {
    const userId = req.userId;

    const user = await User.findById(userId).select(
      "-password -otp -otpExpire"
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({ message: "User profile fetched successfully", success: true, data: user });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Server error", error: error.message });
  }
};

export const changePassword = async (req, res) => {
  try {
    const { email, oldPassword, newPassword } = req.body;

    if (!email || !oldPassword || !newPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Old password is incorrect" });
    }

    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = newHashedPassword;
    await user.save();

    return res.status(200).json({ message: "Password changed successfully", success: true });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Server error", error: error.message });
  }
};

export const resendOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User does not exist" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    const expireOtp = new Date(Date.now() + 10 * 60 * 1000);

    user.otp = otp;
    user.otpExpire = expireOtp;

    await user.save();

    await sendToOtp({
      user,
      otp,
    });

    return res.status(200).json({ message: "Otp sent successfully", success: true });
  } catch (error) {
    console.log(error);
    return res
      .status(500)
      .json({ message: error.message || "Internal Server Error" });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User does not exist" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    const expireOtp = new Date(Date.now() + 10 * 60 * 1000);

    user.otp = otp;
    user.otpExpire = expireOtp;

    await user.save();

    await sendToOtp({
      user,
      otp,
    });

    return res.status(200).json({ message: "Otp sent successfully", success: true });
  } catch (error) {
    console.log(error);
    return res
      .status(500)
      .json({ message: error.message || "Internal Server Error" });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { email, password, otp } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User does not exist" });
    }

    const { otpExpire } = user;

    if (user.otp !== otp) {
      return res.status(400).json({ message: "Invalid Otp" });
    }

    if (otpExpire < new Date()) {
      return res.status(400).json({ message: "Otp has expired" });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
      });
    }

    const getHashPassword = await bcrypt.hash(password, 10);

    user.password = getHashPassword;

    await user.save();

    return res.status(200).json({ message: "Password reset successfully", success: true });
  } catch (error) {
    console.log(error);
    return res
      .status(500)
      .json({ message: error.message || "Internal Server Error" });
  }
};