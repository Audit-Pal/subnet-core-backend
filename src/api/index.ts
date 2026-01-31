import express, { Application, Request, Response } from 'express';
import dotenv from 'dotenv';
import auditRoutes from "../routes/audit";
import mongoose from "mongoose";

dotenv.config();

const app: Application = express();

app.use(express.json());

app.get('/', (req: Request, res: Response) => {
  res.send('Welcome to Express & TypeScript Server');
});

mongoose.connect(process.env.MONGO_URI || "mongodb://localhost:27017/audits")
  .then(() => console.log("Mongo connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

app.use("/api/audits", auditRoutes);

export default app;