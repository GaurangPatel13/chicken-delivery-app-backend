import Admin from "../models/admin.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import DeliveryBoy from "../models/deliveryBoy.model.js";
import Product from "../models/product.model.js";


export const adminRegister = async (req, res) => {
  try {
    let email = process.env.ADMIN_EMAIL;
    let password = process.env.ADMIN_PASSWORD;
    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ message: "Admin already exists" });
    }
   let hashedPassword = await bcrypt.hash(password, 10);
    password = hashedPassword;
    const newAdmin = new Admin({
      name: "Admin",
      email,
      password,
    });

    await newAdmin.save();

    return res
      .status(201)
      .json({ message: "Admin registered successfully" });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error in registration", error: error.message });
  }
};

export const loginAdmin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { adminId: admin._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(200).json({ token, message: "Login successful" });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error in login", error: error.message });
  }
};

export const getAdminProfile = async (req, res) => {
  try {
    const adminId = req.adminId;    
    const admin = await Admin.findById(adminId).select("-password");

    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    return res.status(200).json({ admin });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error fetching profile", error: error.message });
  }
};

export const getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select("-password -otp -otpExpire");
    return res.status(200).json({ users });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error fetching users", error: error.message });
  }
};

export const getAllDeliveryBoys = async (req, res) => {
  try {
    const deliveryBoys = await DeliveryBoy.find().select("-password");
    return res.status(200).json({ deliveryBoys });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error fetching delivery boys", error: error.message });
  }
};

export const getAvailableDeliveryBoys = async (req, res) => {
  try {
    const deliveryBoys = await DeliveryBoy.find({ isAvailable: true }).select("-password");
    return res.status(200).json({ deliveryBoys });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error fetching available delivery boys", error: error.message });
  }
};

export const changeAdminPassword = async (req, res) => {
  try {
    const adminId = req.adminId;
    const { oldPassword, newPassword } = req.body;

    const admin = await Admin.findById(adminId);
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    const isMatch = await bcrypt.compare(oldPassword, admin.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Old password is incorrect" });
    }

    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    admin.password = newHashedPassword;
    await admin.save();

    return res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error changing password", error: error.message });
  }
};


export const createProduct = async (req, res) => {
  try {
    const { name, description, price, category, stock } = req.body;

    if (!name || !description || !price || !category || !stock) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const newProduct = new Product({
      name,
      description,
      price,
      category,
      stock,
    });

    await newProduct.save();

    return res.status(201).json({ message: "Product created successfully", product: newProduct });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error creating product", error: error.message });
  }
};

export const getAllProducts = async (req, res) => {
  try {
    const products = await Product.find();
    return res.status(200).json({ products });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error fetching products", error: error.message });
  }
};

export const toggleProductStatus = async (req, res) => {
  try {
    const productId = req.params.id;

    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    product.isActive = !product.isActive;
    await product.save();

    return res.status(200).json({ message: "Product status updated successfully", product });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error updating product status", error: error.message });
  }
};

export const deleteProduct = async (req, res) => {
  try {
    const productId = req.params.id;

    const product = await Product.findByIdAndDelete(productId);
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    return res.status(200).json({ message: "Product deleted successfully" });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ message: "Error deleting product", error: error.message });
  }
};