import express, { Application, Request, Response } from 'express';
import dotenv from 'dotenv';
import auditRoutes from "./routes/audit";
import mongoose from "mongoose";
// For environment variables
dotenv.config();

const app: Application = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/', (req: Request, res: Response) => {
  res.send('Welcome to Express & TypeScript Server');
});

mongoose.connect(process.env.MONGO_URI || "mongodb://localhost:27017/audits")
  .then(() => console.log("Mongo connected"))
  .catch(console.error);

app.use("/api/audits", auditRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
