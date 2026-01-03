import DeliveryBoy from "../models/deliveryBoy.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const registerDeliveryBoy = async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    if (!name || !email || !phone || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingBoy = await DeliveryBoy.findOne({ email });
    if (existingBoy) {
      return res.status(400).json({ message: "Delivery boy already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newDeliveryBoy = new DeliveryBoy({
      name,
      email,
      phone,
      password: hashedPassword,
    });

    await newDeliveryBoy.save();

    return res
      .status(201)
      .json({ message: "Delivery boy registered successfully" });           
    } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error in registration", error: error.message });
  }
};

export const loginDeliveryBoy = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const deliveryBoy = await DeliveryBoy.findOne({ email });
    if (!deliveryBoy) {
      return res.status(404).json({ message: "Delivery boy  not found" });
    }

    const isMatch = await bcrypt.compare(password, deliveryBoy.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { deliveryBoyId: deliveryBoy._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(200).json({
      message: "Login successful",
      token,
    });
  }
    catch (error) { 
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error in login", error: error.message });
  }
};


export const getDeliveryBoyProfile = async (req, res) => {
  try {
    const deliveryBoyId = req.deliveryBoyId;

    const deliveryBoy = await DeliveryBoy.findById(deliveryBoyId).select("-password");
    if (!deliveryBoy) {
      return res.status(404).json({ message: "Delivery boy not found" });
    }

    return res.status(200).json({ deliveryBoy });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error fetching profile", error: error.message });
  }
};  

export const updateAvailability = async (req, res) => {
  try {
    const deliveryBoyId = req.deliveryBoyId;
    const { isAvailable } = req.body;

    const deliveryBoy = await DeliveryBoy.findById(deliveryBoyId);
    if (!deliveryBoy) {
      return res.status(404).json({ message: "Delivery boy not found" });
    }

    deliveryBoy.isAvailable = isAvailable;
    await deliveryBoy.save();       
    return res.status(200).json({ message: "Availability updated successfully" });
    }
    catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error updating availability", error: error.message });
  }
};

export const changePassword = async (req, res) => {
  try {
    const deliveryBoyId = req.deliveryBoyId;
    const { oldPassword, newPassword } = req.body;

    const deliveryBoy = await DeliveryBoy.findById(deliveryBoyId);
    if (!deliveryBoy) {
      return res.status(404).json({ message: "Delivery boy not found" });
    }

    const isMatch = await bcrypt.compare(oldPassword, deliveryBoy.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Old password is incorrect" });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    deliveryBoy.password = hashedNewPassword;
    await deliveryBoy.save();

    return res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error changing password", error: error.message });
  }
};