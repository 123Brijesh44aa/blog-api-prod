import express from "express";
import { resendVerificationEmail } from "../controllers/emailController.js";


const router = new express.Router();

router.route("/resend-verification-email").post(resendVerificationEmail);


export {router};