import express from "express";
import {loginUser, logoutUser, signupUser} from "../controllers/authController";
import {verifyJWT} from "../middlewares/auth.middleware";

const router = express.Router();

router.route("/signup").post(signupUser);
router.route("/login").post(loginUser);
router.route("/logout").post(verifyJWT,logoutUser);
router.route("/forgetPassword").post();
router.route("/resetPassword/:token").patch();
router.route("/refreshToken").post();
router.route("/verifyEmail/:token").get();


export {router};
