import { Router, Request, Response } from "express";
import { Audit } from "../model/Audit";

const router = Router();

//
// CREATE audit
//
router.post("/", async (req: Request, res: Response) => {
   
    try {
        const audit = await Audit.create(req.body);
        res.status(201).json(audit);
    } catch (err: any) {
        res.status(400).json({ error: err.message });
    }
});

//
// GET all audits
//
router.get("/", async (_req: Request, res: Response) => {
    const audits = await Audit.find();
    res.json(audits);
});

//
// GET audit by audit id
//
router.get("/:id", async (req: Request, res: Response) => {
    const audit = await Audit.findOne({ id: req.params.id });

    if (!audit) {
        return res.status(404).json({ error: "Audit not found" });
    }

    res.json(audit);
});

//
// UPDATE audit (PUT = replace)
//
router.put("/:id", async (req, res) => {
  const update = {
    ...req.body,
    id: req.params.id, // 👈 ensure id is always present
  };

  const audit = await Audit.findOneAndUpdate(
    { id: req.params.id },
    update,
    { new: true, runValidators: true }
  );

  if (!audit) {
    return res.status(404).json({ error: "Audit not found" });
  }

  res.json(audit);
});


//
// DELETE audit
//
router.delete("/:id", async (req: Request, res: Response) => {
    const result = await Audit.findOneAndDelete({ id: req.params.id });

    if (!result) {
        return res.status(404).json({ error: "Audit not found" });
    }

    res.status(204).send();
});

export default router;
