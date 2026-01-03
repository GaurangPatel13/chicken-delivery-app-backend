import mongoose from "mongoose";

const addressSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  addressLine1: { type: String, required: true },
  addressLine2: { type: String },
  city: { type: String,  },
  state: { type: String,  },
  phone : {type :Number},
  pincode: { type: String, },
  country: { type: String, default: "India" },
  isDefault: { type: Boolean, default: false } 
}, { timestamps: true });

const Address = mongoose.model("Address", addressSchema);
export default Address;