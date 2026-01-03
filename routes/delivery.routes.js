import express from "express";
import { changePassword, getDeliveryBoyProfile, loginDeliveryBoy, registerDeliveryBoy, updateAvailability } from "../controller/delivery.controller.js";
const router = express.Router();

router.post("/register", registerDeliveryBoy);
router.post("/login", loginDeliveryBoy);
router.get("/profile", getDeliveryBoyProfile);
router.patch("/availability", updateAvailability);
router.patch("/change-password", changePassword);





export default router;