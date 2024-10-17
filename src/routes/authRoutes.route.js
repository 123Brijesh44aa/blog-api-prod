import express from "express";
import {forgetPassword, loginUser, logoutUser, refreshAccessToken, resetPassword, signupUser} from "../controllers/authController.js";
import {verifyJWT} from "../middlewares/auth.middleware.js";

const router = express.Router();

router.route("/signup").post(signupUser);
router.route("/login").post(loginUser);
router.route("/logout").post(verifyJWT,logoutUser);
router.route("/forgetPassword").post(forgetPassword);
router.route("/resetPassword/:token").patch(resetPassword);
router.route("/refreshToken").post(refreshAccessToken);

 

export {router};
