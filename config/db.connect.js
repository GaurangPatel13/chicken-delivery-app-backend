import mongoose from "mongoose"

const DbConnect = async()=>{
    try {
        let conn  = mongoose.connect(process.env.MONGODB_URL)
        console.log("DB connected successfully")
    } catch (error) {
        console.log("Error in DB connection",error)
    }
}


export default DbConnect;