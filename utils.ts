import { z } from "zod";

export const AuditSchema = z.object({
  id: z.string(),
  created_at: z.number(),
  miner_hotkey: z.string(),
  name: z.string(),
  score: z.number().min(0).max(1),
  status: z.string(),
  findings_count: z.object({
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number(),
    info: z.number(),
  }),
  vulnerabilities: z.array(
    z.object({
      id: z.string(),
      title: z.string(),
      severity: z.enum(["critical", "high", "medium", "low", "info"]),
      line: z.number(),
      impact: z.string(),
      description: z.string(),
      recommendation: z.string(),
    })
  ),
});
