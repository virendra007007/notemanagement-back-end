

import jwt from "jsonwebtoken";
import express from "express";

const router = express.Router();

// Middleware to verify token
export async function authToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Authentication required" });
  }

  const token = authHeader.split(" ")[1]; 

  try {
    const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
    console.log("Decoded Token: ", decodedToken);
    req.user = decodedToken; 
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// API to authenticate and check token validity
export async function authenticate(req, res) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Authentication required" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
    res.status(200).json({
      message: "Token verified successfully",
      decodedToken,
    });
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
}

// Route to check token authentication
router.get("/authenticate", authenticate);

export default router;
