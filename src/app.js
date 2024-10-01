import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import helmet from "helmet";
import {router as authRouter}  from "./routes/authRoutes.route.js";
import cookieParser from "cookie-parser";
import {errorHandlerMiddleware} from "./middlewares/errorHandler.middleware.js";
import dotenv from "dotenv";

dotenv.configDotenv();


const app = express();

// Middleware
app.use(cors(
    {
        origin: process.env.CORS_ORIGIN,
        credentials: true
    }
));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(cookieParser());
// Set Security HTTP headers: helmet is a package which will set some http headers for security reasons
app.use(helmet());

// todo: Rate Limiter

// todo : Data Sanitization against MySQL query injection ( don't worry prisma uses Parameterized queries by default )

// todo: Data Sanitization against XSS

// todo: Prevent Parameter Pollution using hpp


app.use('/api/v2/blog', authRouter);

app.use(errorHandlerMiddleware);


export default app;

