import express from "express";
import {loginUser, logoutUser, refreshAccessToken, signupUser} from "../controllers/authController.js";
import {verifyJWT} from "../middlewares/auth.middleware.js";

const router = express.Router();

router.route("/signup").post(signupUser);
router.route("/login").post(loginUser);
router.route("/logout").post(verifyJWT,logoutUser);
router.route("/forgetPassword").post();
router.route("/resetPassword/:token").patch();
router.route("/refreshToken").post(refreshAccessToken);
router.route("/verifyEmail/:token").get();


export {router};
