import express from "express";
import { auth } from "./lib/auth.js";
import { fromNodeHeaders, toNodeHandler } from "better-auth/node";
import cors from "cors";

const app = express();
const port = 3005;

app.use(
  cors({
    origin: "http://localhost:3000", 
    methods: ["GET", "POST", "PUT", "DELETE"], 
    credentials: true, 
  })
);

app.all("/api/auth/*splat", toNodeHandler(auth)); 

app.use(express.json());

// Fixed: This endpoint now properly handles Bearer token authentication
app.get("/api/me", async (req, res) => {
  try {
    const session = await auth.api.getSession({
      headers: fromNodeHeaders(req.headers),
    });
    
    if (!session) {
      return res.status(401).json({ error: "No active session" });
    }
    
    return res.json(session);
  } catch (error) {
    console.error("Session error:", error);
    return res.status(500).json({ error: "Failed to get session", details: error.message });
  }
});

// You can remove this endpoint if you're using the Bearer token approach above
app.get("/api/me/:access_token", async (req, res) => {
  const { access_token } = req.params;
  console.log(access_token);
  
  try {
    const session = await auth.api.getSession({
      headers: {
        authorization: `Bearer ${access_token}`
      }
    });
    
    if (!session) {
      return res.status(401).json({ error: "Invalid token" });
    }
    
    return res.json(session);
  } catch (error) {
    console.error("Token validation error:", error);
    return res.status(401).json({ error: "Unauthorized", details: error.message });
  }
});

app.get("/device", async (req, res) => {
  const { user_code } = req.query; // Fixed: should be req.query, not req.params
  res.redirect(`http://localhost:3000/device?user_code=${user_code}`);
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});