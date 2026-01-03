import mongoose from "mongoose";

const adminSchema = new mongoose.Schema({
  name: { type: String,  },
  email: { type: String, unique: true },

}, { timestamps: true });

const Admin = mongoose.model("Admin", adminSchema);
export default Admin; 