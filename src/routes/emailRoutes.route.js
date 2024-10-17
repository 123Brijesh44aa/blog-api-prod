import express from "express";
import { verifyEmail, resendVerificationEmail } from "../controllers/emailController.js";


const router = new express.Router();

router.route("/resend-verification-email").post(resendVerificationEmail);
router.route("/verifyEmail/:token").get(verifyEmail);


export {router};