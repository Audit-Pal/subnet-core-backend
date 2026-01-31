import { Schema, model, Document } from "mongoose";

export interface Vulnerability {
    id: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    line: number;
    impact: string;
    description: string;
    recommendation: string;
}

export interface AuditDocument extends Document {
    id: string;
    created_at: number;
    miner_hotkey: string;
    name: string;
    score: number;
    status: string;
    findings_count: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    vulnerabilities: Vulnerability[];
}

const VulnerabilitySchema = new Schema<Vulnerability>({
    id: { type: String, required: true },
    title: String,
    severity: {
        type: String,
        enum: ["critical", "high", "medium", "low", "info"],
        required: true,
    },
    line: Number,
    impact: String,
    description: String,
    recommendation: String,
});

const AuditSchema = new Schema<AuditDocument>({
    id: { type: String, required: true, unique: true },
    created_at: Number,
    miner_hotkey: String,
    name: String,
    score: Number,
    status: String,
    findings_count: {
        critical: Number,
        high: Number,
        medium: Number,
        low: Number,
        info: Number,
    },
    vulnerabilities: [VulnerabilitySchema],
});

export const Audit = model<AuditDocument>("Audit", AuditSchema);
