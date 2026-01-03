import mongoose from "mongoose";

const deliveryBoySchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAvailable: { type: Boolean, default: true },
}, { timestamps: true });

const DeliveryBoy = mongoose.model("DeliveryBoy", deliveryBoySchema);
export default DeliveryBoy; 