import  express from "express";
import {signup, signin} from "../controllers/auth.js"




const router = express.Router();

// Create a User 
router.post("/signup",signup)




// Sign In 
router.post("/signIn",signin)

// Google Auth
router.post("/google",)





export default router;