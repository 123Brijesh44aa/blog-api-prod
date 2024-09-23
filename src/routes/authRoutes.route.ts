import express from "express";
import {signupUser} from "../controllers/authController";

const router = express.Router();

router.route("/signup").post(signupUser);
router.route("/login").post();
router.route("/forgetPassword").post();
router.route("/resetPassword/:token").patch();
router.route("/refreshToken").post();
router.route("/logout").post();
router.route("/verifyEmail/:token").get();


export {router};
