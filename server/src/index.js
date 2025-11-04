import express from "express";
import { toNodeHandler } from "better-auth/node";
import { auth } from "./lib/auth.js";


const app = express();
const port = 3005;

app.all("/api/auth/*splat", toNodeHandler(auth)); 


app.use(express.json());

app.listen(port, () => {
	console.log(`Example app listening on port ${port}`);
});