import Address from "../models/address.model.js";
import User from "../models/user.model.js";

export const  addAddress = async (req, res) => {
    try {
        const userId = req.user._id || req.user_id;

        const { addressLine1, addressLine2, city, state, pincode, country, phone, isDefault } = req.body;

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        // Agar naya address default hai → purane sab default false
        if (isDefault) {
            await Address.updateMany({ user: userId }, { $set: { isDefault: false } });
        }

        const address = new Address({
            user: userId,
            addressLine1,
            addressLine2,
            city,
            state,
            pincode,
            country,
            phone,
            isDefault,
        });

        user.addresses.push(address._id);
        await user.save();
        await address.save();

        return res.status(201).json({
            message: "Address added successfully",
            success: true,
            address,
        });
    } catch (error) {
        console.error("Error adding address:", error);
        return res.status(500).json({ message: error.message, success: false });
    }
};


export const getUserAddresses = async (req, res) => {
    try {
        const userId = req.user._id;
        const addresses = await Address.find({ user: userId }).populate("user", "name email mobile");
        return res.status(200).json({ addresses });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: error.message, success: false });
    }
};
//Shipping Address
export const updateAddress = async (req, res) => {
    try {
        // const { addressId } = req.params;
        const { addressLine1, addressId, addressLine2, city, state, pincode, country, isDefault } = req.body;
        console.log(req.body)
        if (isDefault === true || isDefault === "true") {
            await Address.updateMany(
                { user: req.body.userId || req.user._id },
                { $set: { isDefault: false } }
            );
        }

        const updatedAddress = await Address.findByIdAndUpdate(addressId, { addressLine1, addressLine2, city, state, pincode, country, isDefault }, { new: true });

        if (!updatedAddress) return res.status(404).json({ message: "Address not found" });

        return res.status(200).json({ message: "Address updated successfully", updatedAddress });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: error.message, success: false });
    }
};
export const deleteAddress = async (req, res) => {
    try {
        const { addressId } = req.params;
        const userId = req.user;
        // console.log(userId, "userId");
        const deletedAddress = await Address.findByIdAndDelete(addressId);
        if (!deletedAddress) return res.status(404).json({ message: "Address not found" });
        await User.findByIdAndUpdate(userId, { $pull: { addresses: addressId } });

        return res.status(200).json({ message: "Address deleted successfully", success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error deleting address", success: false, error });
    }
};
export const setDefaultAddress = async (req, res) => {
    try {
        const {  addressId } = req.body;
        let user_Id = req.user._id ;

        await Address.updateMany({ user: user_Id }, { $set: { isDefault: false } });

        const updatedAddress = await Address.findByIdAndUpdate(addressId, { isDefault: true }, { new: true });

        if (!updatedAddress) return res.status(404).json({ message: "Address not found" });

        return res.status(200).json({ message: "Default address updated", updatedAddress, success: true });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: error.message, success: false });
    }
};
