import express from "express";
import serverless from "serverless-http";
import dotenv from "dotenv";
import mongoose from "mongoose";
import auditRoutes from "./routes/audit";

dotenv.config();

const app = express();
app.use(express.json());

mongoose.connect(process.env.MONGO_URI!)
  .then(() => console.log("Mongo connected"))
  .catch(console.error);

app.use("/api/audits", auditRoutes);

export default serverless(app);
