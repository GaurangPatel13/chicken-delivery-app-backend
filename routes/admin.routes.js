import express from "express";
import {
  adminRegister,
  loginAdmin,
  getAdminProfile,
  getAllDeliveryBoys,
  getAllProducts,
  getAllUsers,
  getAvailableDeliveryBoys,
  toggleProductStatus,
  deleteProduct,
  changeAdminPassword,
  createProduct,
} from "../controller/admin.controller.js";
import adminAuth from "../middleware/adminAuth.js";
const router = express.Router();

router.post("/register", adminRegister);
router.post("/login", loginAdmin);
router.get("/profile", getAdminProfile);
router.get("/users", getAllUsers);
router.get("/delivery-boys", getAllDeliveryBoys);
router.get("/delivery-boys/available", getAvailableDeliveryBoys);
router.get("/products", getAllProducts);
router.post("/change-password", changeAdminPassword);
router.post("/products", createProduct);
router.patch("/products/:productId/toggle-status", toggleProductStatus);
router.delete("/products/:productId", deleteProduct);





export default router;