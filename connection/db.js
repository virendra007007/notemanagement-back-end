import dotenv from "dotenv";
dotenv.config();
import mongoose from "mongoose";


mongoose.connect(
  `mongodb+srv://${process.env.MONGODB_NAME}:${process.env.MONGODB_PASSWORD}@cluster1.q5t9j.mongodb.net/notemanagement`
).then(()=>{
    console.log("Connected to MongoDB");
}).catch(()=>{
    console.log("Error connecting to MongoDB");
})
