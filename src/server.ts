import app from "./app";
import dotenv from "dotenv";
import {checkDatabaseConnection} from "./db";

dotenv.config();

const PORT = process.env.PORT || 3000;

app.listen(PORT, async() => {
    console.log(`App running on port ${PORT}...`);
    await checkDatabaseConnection();
});

