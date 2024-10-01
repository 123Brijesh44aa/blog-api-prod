import app from "./app.js";
import dotenv from "dotenv";
import {checkDatabaseConnection} from "./db.js";

dotenv.config();

const PORT = process.env.PORT || 3000;

app.listen(PORT, async() => {
    console.log(`App running on port ${PORT}...`);
    await checkDatabaseConnection();
});

