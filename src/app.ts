import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import helmet from "helmet";
import {router as authRouter}  from "./routes/authRoutes.route";

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

// Set Security HTTP headers: helmet is a package which will set some http headers for security reasons
app.use(helmet());

// todo: Rate Limiter

// todo : Data Sanitization against MySQL query injection ( don't worry prisma uses Parameterized queries by default )

// todo: Data Sanitization against XSS

// todo: Prevent Parameter Pollution using hpp


app.use("/api/v2/blog", authRouter);


export default app;

