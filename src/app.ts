import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import helmet from "helmet";

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

// Set Security HTTP headers: helmet is a package which will set some http headers for security reasons
app.use(helmet());

// todo: Rate Limiter

// todo : Data Sanitization against

// todo: Prevent Parameter Pollution using hpp


export default app;

