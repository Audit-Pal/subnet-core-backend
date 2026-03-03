import express, { Request, Response, NextFunction, Express } from 'express';
import mongoose, { Schema, Document, Model } from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import mongoSanitize from 'express-mongo-sanitize';

dotenv.config();

// =====================
// ENV VALIDATION — fail fast if secrets are missing
// =====================
const REQUIRED_ENV = ['MONGO_URI', 'API_KEY'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`✗ Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

const API_KEY = process.env.API_KEY!;

const app: Express = express();

// =====================
// SECURITY HEADERS (helmet)
// =====================
app.use(helmet());

// =====================
// CORS — lock down to known origins
// =====================
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // Allow no-origin requests (curl, server-to-server) only in dev
    if (!origin) {
      return process.env.NODE_ENV === 'production'
        ? cb(new Error('Origin required in production'))
        : cb(null, true);
    }
    if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
      cb(null, true);
    } else {
      cb(new Error(`CORS: origin ${origin} not allowed`));
    }
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'x-api-key']
}));

// =====================
// BODY PARSING — tight size limit
// =====================
app.use(express.json({ limit: '1mb' }));        // was 50mb — no endpoint needs that
app.use(express.urlencoded({ limit: '1mb', extended: true }));

// =====================
// MONGO INJECTION SANITIZATION
// Strips $ and . from req.body, req.params, req.query
// =====================
app.use(mongoSanitize());

// =====================
// REQUEST LOGGING
// =====================
app.use((req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    // Never log body — could contain sensitive data
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
  });
  next();
});

// =====================
// RATE LIMITERS
// =====================

// Strict limiter for session creation (write-heavy, expensive)
const startSessionLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,                          // 10 new sessions per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many session requests, slow down.' }
});

// General write limiter for session sub-routes
const writeLimiter = rateLimit({
  windowMs: 60_000,
  max: 120,                         // 2/sec average
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests.' }
});

// Relaxed limiter for read endpoints (dashboard polling)
const readLimiter = rateLimit({
  windowMs: 60_000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests.' }
});

// =====================
// AUTH MIDDLEWARE
// =====================

/**
 * requireApiKey — verifies x-api-key header matches API_KEY env var.
 * Applied to all write (POST) endpoints.
 */
const requireApiKey = (req: Request, res: Response, next: NextFunction): void => {
  const key = req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    res.status(401).json({ success: false, error: 'Unauthorized' });
    return;
  }
  next();
};

/**
 * verifySessionOwner — after requireApiKey, checks that the requesting
 * validator is the one who created this session.
 * Reads validatorAddress from req.body and compares against session metadata.
 */
const verifySessionOwner = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { sessionId } = req.params;
    const validatorAddress = req.body?.validatorAddress || req.body?._meta?.hotkey;

    if (!validatorAddress) {
      res.status(400).json({ success: false, error: 'validatorAddress is required' });
      return;
    }

    const session = await ValidationSession.findOne(
      { sessionId },
      { 'metadata.validatorAddress': 1 }
    ).lean();

    if (!session) {
      res.status(404).json({ success: false, error: 'Session not found' });
      return;
    }

    if ((session as any).metadata?.validatorAddress !== validatorAddress) {
      res.status(403).json({ success: false, error: 'Forbidden: session belongs to another validator' });
      return;
    }

    next();
  } catch (err: any) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
};

// =====================
// INPUT VALIDATORS
// =====================

/** Reject strings over maxLen to prevent oversized payloads slipping through */
const safeStr = (val: unknown, maxLen = 512): string | undefined => {
  if (typeof val !== 'string') return undefined;
  return val.slice(0, maxLen);
};

/** Clamp a number to a safe range */
const safeNum = (val: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): number | undefined => {
  const n = Number(val);
  if (!isFinite(n)) return undefined;
  return Math.min(Math.max(n, min), max);
};

/** Validate reward score is a real number in [0, 1] */
const isValidScore = (val: unknown): val is number =>
  typeof val === 'number' && isFinite(val) && val >= 0 && val <= 1;

// =====================
// INTERFACES
// =====================

interface MinerResponse {
  minerUid: number;
  githubUrl?: string;
  responseTime: number;
  success: boolean;
  errorMessage?: string;
  timestamp: Date;
  agentPerformance?: {
    executionTime?: number;
    findingsCount?: number;
    accuracy?: number;
    completionStatus?: string;
  };
  rewardScore?: number;
  rewardReason?: string;
}

interface ChallengeInfo {
  projectId: string;
  description?: string;
  difficulty?: string;
  createdAt: Date;
  rawData?: Record<string, any>;
}

interface SubnetSnapshot {
  netuid: number;
  block: number;
  activeValidators: number;
  activeMiners: number;
  totalStake: number;
  emissionPerBlock: number;
  timestamp: Date;
}

interface ValidationMetrics {
  totalQueryTime?: number;
  averageRewardScore?: number;
  successRate?: number;
  failureCount?: number;
  validFindings?: number;
}

interface ValidationSessionDocument extends Document {
  sessionId: string;
  timestamp: Date;
  projectId?: string;
  projectName?: string;
  state: 'pending' | 'in-progress' | 'completed' | 'failed';
  sampledMinerCount: number;
  sampledMinerUids: number[];
  challengeInfo: ChallengeInfo;
  minerResponses: MinerResponse[];
  computedRewards: Array<{ minerUid: number; score: number; timestamp: Date }>;
  metrics: ValidationMetrics;
  subnetSnapshot: SubnetSnapshot;
  validationErrors: Array<{
    stage: string;
    message: string;
    timestamp: Date;
    stackTrace?: string;
  }>;
  metadata: {
    validatorAddress?: string;
    configVersion?: string;
    remarks?: string;
  };
}

interface MinerHistoryDocument extends Document {
  minerUid: number;
  sessionId: string;
  performanceScore?: number;
  rewardScore: number;
  githubUrl?: string;
  findingsCount?: number;
  accuracy?: number;
  executionTime?: number;
  timestamp: Date;
  status: 'success' | 'failed' | 'timeout' | 'error';
}

interface RewardUpdateDocument extends Document {
  updateId: string;
  sessionId: string;
  minerUids: number[];
  rewards: number[];
  timestamp: Date;
  confirmed: boolean;
  confirmationTime?: Date;
}

// =====================
// DATABASE SCHEMAS
// =====================

const validationSessionSchema = new Schema<ValidationSessionDocument>({
  sessionId: { type: String, required: true, unique: true, index: true },
  timestamp: { type: Date, default: Date.now, index: true },
  projectId: String,
  projectName: String,
  state: {
    type: String,
    enum: ['pending', 'in-progress', 'completed', 'failed'],
    default: 'pending'
  },
  sampledMinerCount: Number,
  sampledMinerUids: [Number],
  challengeInfo: {
    projectId: String,
    description: String,
    difficulty: String,
    createdAt: Date,
    rawData: Schema.Types.Mixed
  },
  minerResponses: [{
    minerUid: Number,
    githubUrl: String,
    responseTime: Number,
    success: Boolean,
    errorMessage: String,
    timestamp: Date,
    agentPerformance: {
      executionTime: Number,
      findingsCount: Number,
      accuracy: Number,
      completionStatus: String
    },
    rewardScore: Number,
    rewardReason: String,
    _id: false
  }],
  computedRewards: [{
    minerUid: Number,
    score: Number,
    timestamp: Date,
    _id: false
  }],
  metrics: {
    totalQueryTime: Number,
    averageRewardScore: Number,
    successRate: Number,
    failureCount: Number,
    validFindings: Number
  },
  subnetSnapshot: {
    netuid: Number,
    block: Number,
    activeValidators: Number,
    activeMiners: Number,
    totalStake: Number,
    emissionPerBlock: Number,
    timestamp: Date
  },
  validationErrors: [{
    stage: String,
    message: String,
    timestamp: Date,
    stackTrace: String,
    _id: false
  }],
  metadata: {
    validatorAddress: String,
    configVersion: String,
    remarks: String
  }
});

const minerHistorySchema = new Schema<MinerHistoryDocument>({
  minerUid: { type: Number, required: true, index: true },
  sessionId: { type: String, required: true, index: true },
  performanceScore: Number,
  rewardScore: Number,
  githubUrl: String,
  findingsCount: Number,
  accuracy: Number,
  executionTime: Number,
  timestamp: { type: Date, default: Date.now, index: true },
  status: { type: String, enum: ['success', 'failed', 'timeout', 'error'] }
});

const rewardUpdateSchema = new Schema<RewardUpdateDocument>({
  updateId: { type: String, required: true, unique: true },
  sessionId: { type: String, required: true, index: true },
  minerUids: [Number],
  rewards: [Number],
  timestamp: { type: Date, default: Date.now, index: true },
  confirmed: { type: Boolean, default: false },
  confirmationTime: Date
});

validationSessionSchema.index({ timestamp: -1 });
minerHistorySchema.index({ minerUid: 1, timestamp: -1 });
rewardUpdateSchema.index({ sessionId: 1, timestamp: -1 });

// =====================
// MODELS
// =====================

const ValidationSession: Model<ValidationSessionDocument> = mongoose.model(
  'ValidationSession',
  validationSessionSchema
);

const MinerHistory: Model<MinerHistoryDocument> = mongoose.model(
  'MinerHistory',
  minerHistorySchema
);

const RewardUpdate: Model<RewardUpdateDocument> = mongoose.model(
  'RewardUpdate',
  rewardUpdateSchema
);

// ─────────────────────────────────────────────────────────────
// WRITE ENDPOINTS  (requireApiKey + writeLimiter on all)
// ─────────────────────────────────────────────────────────────

/**
 * POST /api/validation/start
 */
app.post(
  '/api/validation/start',
  requireApiKey,
  startSessionLimiter,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { sampledMinerUids, validatorAddress, configVersion } = req.body;

      if (!Array.isArray(sampledMinerUids) || sampledMinerUids.length === 0) {
        res.status(400).json({ success: false, error: 'sampledMinerUids must be a non-empty array' });
        return;
      }

      // Sanitize: ensure every element is a finite integer UID
      const cleanUids: number[] = sampledMinerUids
        .map((u: unknown) => Math.floor(Number(u)))
        .filter((u: number) => isFinite(u) && u >= 0);

      if (cleanUids.length === 0) {
        res.status(400).json({ success: false, error: 'sampledMinerUids contains no valid UIDs' });
        return;
      }

      // Cap to 256 miners per session to prevent abuse
      if (cleanUids.length > 256) {
        res.status(400).json({ success: false, error: 'sampledMinerUids exceeds maximum of 256' });
        return;
      }

      if (!validatorAddress || typeof validatorAddress !== 'string') {
        res.status(400).json({ success: false, error: 'validatorAddress is required' });
        return;
      }

      const sessionId = uuidv4();

      const session = new ValidationSession({
        sessionId,
        sampledMinerCount: cleanUids.length,
        sampledMinerUids: cleanUids,
        state: 'pending',
        metadata: {
          validatorAddress: safeStr(validatorAddress, 64),
          configVersion: safeStr(configVersion, 32)
        },
        minerResponses: [],
        computedRewards: [],
        validationErrors: []
      });

      await session.save();

      res.status(201).json({
        success: true,
        sessionId,
        message: 'Validation session started',
        timestamp: new Date()
      });
    } catch (error: any) {
      console.error('Error in POST /api/validation/start:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

/**
 * POST /api/validation/:sessionId/challenge
 */
app.post(
  '/api/validation/:sessionId/challenge',
  requireApiKey,
  writeLimiter,
  verifySessionOwner,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const { projectId, description, difficulty, rawData } = req.body;

      if (!projectId || typeof projectId !== 'string') {
        res.status(400).json({ success: false, error: 'projectId is required' });
        return;
      }

      const VALID_DIFFICULTIES = ['easy', 'medium', 'hard', 'critical'];
      const cleanDifficulty = VALID_DIFFICULTIES.includes(difficulty) ? difficulty : undefined;

      const session = await ValidationSession.findOneAndUpdate(
        { sessionId },
        {
          $set: {
            state: 'in-progress',
            projectId: safeStr(projectId, 128),
            'challengeInfo.projectId': safeStr(projectId, 128),
            'challengeInfo.description': safeStr(description, 2048),
            'challengeInfo.difficulty': cleanDifficulty,
            // rawData stored as-is but mongo-sanitize already stripped operators
            'challengeInfo.rawData': rawData || {},
            'challengeInfo.createdAt': new Date()
          }
        },
        { new: true }
      );

      if (!session) {
        res.status(404).json({ success: false, error: 'Session not found' });
        return;
      }

      res.json({ success: true, message: 'Challenge recorded', projectId });
    } catch (error: any) {
      console.error('Error in POST /api/validation/:sessionId/challenge:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

/**
 * POST /api/validation/:sessionId/miner-response
 */
app.post(
  '/api/validation/:sessionId/miner-response',
  requireApiKey,
  writeLimiter,
  verifySessionOwner,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const { minerUid, githubUrl, responseTime, success, errorMessage, agentPerformance } = req.body;

      const cleanUid = Math.floor(Number(minerUid));
      if (!isFinite(cleanUid) || cleanUid < 0) {
        res.status(400).json({ success: false, error: 'minerUid must be a non-negative integer' });
        return;
      }

      // Validate githubUrl is actually a GitHub URL
      let cleanGithubUrl: string | undefined;
      if (githubUrl) {
        try {
          const u = new URL(String(githubUrl));
          if (u.hostname !== 'github.com') throw new Error('Not github.com');
          cleanGithubUrl = u.href.slice(0, 256);
        } catch {
          res.status(400).json({ success: false, error: 'githubUrl must be a valid github.com URL' });
          return;
        }
      }

      const cleanResponseTime = safeNum(responseTime, 0, 3_600_000); // max 1 hour in ms

      const VALID_STATUSES = ['completed', 'error', 'timeout', 'no_response'];
      const completionStatus = VALID_STATUSES.includes(agentPerformance?.completionStatus)
        ? agentPerformance.completionStatus
        : undefined;

      const session = await ValidationSession.findOneAndUpdate(
        { sessionId },
        {
          $push: {
            minerResponses: {
              minerUid: cleanUid,
              githubUrl: cleanGithubUrl,
              responseTime: cleanResponseTime,
              success: Boolean(success),
              errorMessage: safeStr(errorMessage, 512),
              timestamp: new Date(),
              agentPerformance: {
                executionTime: safeNum(agentPerformance?.executionTime, 0, 3_600_000),
                findingsCount: safeNum(agentPerformance?.findingsCount, 0, 10_000),
                accuracy: safeNum(agentPerformance?.accuracy, 0, 1),
                completionStatus
              },
              rewardScore: isValidScore(req.body.rewardScore) ? req.body.rewardScore : undefined,
              rewardReason: safeStr(req.body.rewardReason, 256)
            }
          }
        },
        { new: true }
      );

      if (!session) {
        res.status(404).json({ success: false, error: 'Session not found' });
        return;
      }

      res.json({ success: true, message: 'Miner response recorded', minerUid: cleanUid });
    } catch (error: any) {
      console.error('Error in POST /api/validation/:sessionId/miner-response:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

/**
 * POST /api/validation/:sessionId/miner-reward
 */
app.post(
  '/api/validation/:sessionId/miner-reward',
  requireApiKey,
  writeLimiter,
  verifySessionOwner,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const { minerUid, rewardScore, rewardReason } = req.body;

      const cleanUid = Math.floor(Number(minerUid));
      if (!isFinite(cleanUid) || cleanUid < 0) {
        res.status(400).json({ success: false, error: 'minerUid must be a non-negative integer' });
        return;
      }

      if (!isValidScore(rewardScore)) {
        res.status(400).json({ success: false, error: 'rewardScore must be a number between 0 and 1' });
        return;
      }

      const session = await ValidationSession.findOneAndUpdate(
        { sessionId, 'minerResponses.minerUid': cleanUid },
        {
          $set: {
            'minerResponses.$.rewardScore': rewardScore,
            'minerResponses.$.rewardReason': safeStr(rewardReason, 256)
          }
        },
        { new: true }
      );

      if (!session) {
        res.status(404).json({ success: false, error: 'Session or miner response not found' });
        return;
      }

      await MinerHistory.create({
        minerUid: cleanUid,
        sessionId,
        rewardScore,
        timestamp: new Date(),
        status: rewardScore > 0 ? 'success' : 'failed'
      });

      res.json({ success: true, message: 'Reward recorded', minerUid: cleanUid, rewardScore });
    } catch (error: any) {
      console.error('Error in POST /api/validation/:sessionId/miner-reward:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

/**
 * POST /api/validation/:sessionId/rewards-update
 */
app.post(
  '/api/validation/:sessionId/rewards-update',
  requireApiKey,
  writeLimiter,
  verifySessionOwner,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const { minerUids, rewards } = req.body;

      if (!Array.isArray(minerUids) || !Array.isArray(rewards)) {
        res.status(400).json({ success: false, error: 'minerUids and rewards must be arrays' });
        return;
      }

      if (minerUids.length !== rewards.length) {
        res.status(400).json({ success: false, error: 'minerUids and rewards must have the same length' });
        return;
      }

      if (minerUids.length > 256) {
        res.status(400).json({ success: false, error: 'Batch exceeds maximum of 256 miners' });
        return;
      }

      // Sanitize every value
      const cleanUids = minerUids.map((u: unknown) => Math.floor(Number(u)));
      const cleanRewards = rewards.map((r: unknown) => {
        const n = Number(r);
        return isFinite(n) ? Math.min(Math.max(n, 0), 1) : 0;
      });

      if (cleanUids.some((u: number) => !isFinite(u) || u < 0)) {
        res.status(400).json({ success: false, error: 'All minerUids must be non-negative integers' });
        return;
      }

      const updateId = uuidv4();

      await RewardUpdate.create({ updateId, sessionId, minerUids: cleanUids, rewards: cleanRewards });

      const session = await ValidationSession.findOne({ sessionId });
      if (session) {
        session.computedRewards = cleanUids.map((uid: number, idx: number) => ({
          minerUid: uid,
          score: cleanRewards[idx],
          timestamp: new Date()
        }));

        const successCount = cleanRewards.filter((r: number) => r > 0).length;
        session.metrics = {
          successRate: (successCount / cleanUids.length) * 100,
          averageRewardScore: cleanRewards.reduce((a: number, b: number) => a + b, 0) / cleanUids.length,
          failureCount: cleanUids.length - successCount
        };

        await session.save();
      }

      res.json({ success: true, message: 'Rewards updated', updateId, minerCount: cleanUids.length });
    } catch (error: any) {
      console.error('Error in POST /api/validation/:sessionId/rewards-update:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

/**
 * POST /api/validation/:sessionId/subnet-snapshot
 */
app.post(
  '/api/validation/:sessionId/subnet-snapshot',
  requireApiKey,
  writeLimiter,
  verifySessionOwner,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const { netuid, block, activeValidators, activeMiners, totalStake, emissionPerBlock } = req.body;

      if (typeof netuid !== 'number' || typeof block !== 'number') {
        res.status(400).json({ success: false, error: 'netuid and block must be numbers' });
        return;
      }

      await ValidationSession.findOneAndUpdate(
        { sessionId },
        {
          $set: {
            'subnetSnapshot.netuid': safeNum(netuid, 0, 65535),
            'subnetSnapshot.block': safeNum(block, 0),
            'subnetSnapshot.activeValidators': safeNum(activeValidators, 0, 10_000),
            'subnetSnapshot.activeMiners': safeNum(activeMiners, 0, 100_000),
            'subnetSnapshot.totalStake': safeNum(totalStake, 0),
            'subnetSnapshot.emissionPerBlock': safeNum(emissionPerBlock, 0),
            'subnetSnapshot.timestamp': new Date()
          }
        }
      );

      res.json({ success: true, message: 'Subnet snapshot recorded' });
    } catch (error: any) {
      console.error('Error in POST /api/validation/:sessionId/subnet-snapshot:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

/**
 * POST /api/validation/:sessionId/error
 */
app.post(
  '/api/validation/:sessionId/error',
  requireApiKey,
  writeLimiter,
  verifySessionOwner,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const { stage, message, stackTrace } = req.body;

      if (!stage || !message) {
        res.status(400).json({ success: false, error: 'stage and message are required' });
        return;
      }

      const VALID_STAGES = [
        'session-start', 'challenge-fetch', 'ground-truth-fetch',
        'miner-query', 'miner-processing', 'rewards-update',
        'subnet-snapshot', 'validator-critical'
      ];

      const cleanStage = VALID_STAGES.includes(stage) ? stage : 'unknown';

      await ValidationSession.findOneAndUpdate(
        { sessionId },
        {
          $push: {
            validationErrors: {
              stage: cleanStage,
              message: safeStr(message, 1024),
              timestamp: new Date(),
              // Strip stack traces in production — they can leak internal paths
              stackTrace: process.env.NODE_ENV !== 'production'
                ? safeStr(stackTrace, 4096)
                : undefined
            }
          }
        }
      );

      res.json({ success: true, message: 'Error logged' });
    } catch (error: any) {
      console.error('Error in POST /api/validation/:sessionId/error:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

/**
 * POST /api/validation/:sessionId/complete
 */
app.post(
  '/api/validation/:sessionId/complete',
  requireApiKey,
  writeLimiter,
  verifySessionOwner,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const { metrics } = req.body;

      const session = await ValidationSession.findOneAndUpdate(
        { sessionId },
        {
          $set: {
            state: 'completed',
            'metrics.totalQueryTime': safeNum(metrics?.totalQueryTime, 0, 86_400_000),
            'metrics.averageRewardScore': safeNum(metrics?.averageRewardScore, 0, 1),
            'metrics.successRate': safeNum(metrics?.successRate, 0, 100),
            'metrics.failureCount': safeNum(metrics?.failureCount, 0, 10_000),
            'metrics.validFindings': safeNum(metrics?.validFindings, 0, 100_000)
          }
        },
        { new: true }
      );

      if (!session) {
        res.status(404).json({ success: false, error: 'Session not found' });
        return;
      }

      res.json({ success: true, message: 'Validation session completed', sessionId });
    } catch (error: any) {
      console.error('Error in POST /api/validation/:sessionId/complete:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

// ─────────────────────────────────────────────────────────────
// READ ENDPOINTS  (readLimiter only — public dashboard data)
// ─────────────────────────────────────────────────────────────

app.get('/api/validation/:sessionId', readLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    const { sessionId } = req.params;
    const session = await ValidationSession.findOne({ sessionId });
    if (!session) {
      res.status(404).json({ success: false, error: 'Session not found' });
      return;
    }
    res.json({ success: true, data: session });
  } catch (error: any) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/validation/sessions/recent', readLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100); // cap at 100
    const skip  = Math.max(parseInt(req.query.skip as string) || 0, 0);

    const sessions = await ValidationSession.find()
      .sort({ timestamp: -1 })
      .limit(limit)
      .skip(skip)
      .select('-challengeInfo.rawData -validationErrors.stackTrace'); // strip internal fields

    const total = await ValidationSession.countDocuments();

    res.json({ success: true, data: sessions, pagination: { total, limit, skip } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/validation/sessions/stats', readLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    const { timeRange = '24h' } = req.query;
    const startDate = new Date();
    if (timeRange === '7d')       startDate.setDate(startDate.getDate() - 7);
    else if (timeRange === '30d') startDate.setDate(startDate.getDate() - 30);
    else                          startDate.setHours(startDate.getHours() - 24);

    const stats = await ValidationSession.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      {
        $group: {
          _id: null,
          totalSessions:      { $sum: 1 },
          completedSessions:  { $sum: { $cond: [{ $eq: ['$state', 'completed'] }, 1, 0] } },
          failedSessions:     { $sum: { $cond: [{ $eq: ['$state', 'failed'] }, 1, 0] } },
          avgRewardScore:     { $avg: '$metrics.averageRewardScore' },
          totalMinersQueried: { $sum: '$sampledMinerCount' },
          avgQueryTime:       { $avg: '$metrics.totalQueryTime' }
        }
      }
    ]);

    res.json({
      success: true, timeRange,
      data: stats[0] || { totalSessions: 0, completedSessions: 0, failedSessions: 0, avgRewardScore: 0, totalMinersQueried: 0, avgQueryTime: 0 }
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/miners/:minerUid/history', readLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    const minerIdNum = parseInt(req.params.minerUid);
    if (!isFinite(minerIdNum) || minerIdNum < 0) {
      res.status(400).json({ success: false, error: 'Invalid minerUid' });
      return;
    }

    const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);

    const history = await MinerHistory.find({ minerUid: minerIdNum })
      .sort({ timestamp: -1 })
      .limit(limit);

    const stats = await MinerHistory.aggregate([
      { $match: { minerUid: minerIdNum } },
      {
        $group: {
          _id: null,
          avgReward:           { $avg: '$rewardScore' },
          totalParticipations: { $sum: 1 },
          successCount:        { $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] } },
          failureCount:        { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } },
          avgAccuracy:         { $avg: '$accuracy' }
        }
      }
    ]);

    res.json({
      success: true, minerUid: minerIdNum, history,
      stats: stats[0] || { avgReward: 0, totalParticipations: 0, successCount: 0, failureCount: 0, avgAccuracy: 0 }
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/leaderboard', readLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
    const { timeRange = '30d' } = req.query;

    const startDate = new Date();
    if (timeRange === '24h')     startDate.setHours(startDate.getHours() - 24);
    else if (timeRange === '7d') startDate.setDate(startDate.getDate() - 7);
    else                         startDate.setDate(startDate.getDate() - 30);

    const leaderboard = await MinerHistory.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      {
        $group: {
          _id: '$minerUid',
          totalRewards:       { $sum: '$rewardScore' },
          avgReward:          { $avg: '$rewardScore' },
          participationCount: { $sum: 1 },
          successCount:       { $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] } },
          avgAccuracy:        { $avg: '$accuracy' }
        }
      },
      { $sort: { totalRewards: -1 } },
      { $limit: limit }
    ]);

    res.json({
      success: true, timeRange,
      leaderboard: leaderboard.map((entry: any, idx: number) => ({
        rank:               idx + 1,
        minerUid:           entry._id,
        totalRewards:       entry.totalRewards,
        avgReward:          Number(entry.avgReward?.toFixed(4)) || 0,
        participationCount: entry.participationCount,
        successRate:        Number(((entry.successCount / entry.participationCount) * 100).toFixed(2)) + '%',
        avgAccuracy:        entry.avgAccuracy?.toFixed(4) || 'N/A'
      }))
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/project/:projectId/summary', readLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    const projectId = safeStr(req.params.projectId, 128);
    if (!projectId) {
      res.status(400).json({ success: false, error: 'Invalid projectId' });
      return;
    }

    const sessions = await ValidationSession.find({ projectId }).sort({ timestamp: -1 })
      .select('-challengeInfo.rawData');

    const summary = {
      projectId,
      totalValidationRuns: sessions.length,
      successfulRuns:      sessions.filter((s: any) => s.state === 'completed').length,
      failedRuns:          sessions.filter((s: any) => s.state === 'failed').length,
      totalMinersQueried:  sessions.reduce((acc: number, s: any) => acc + (s.sampledMinerCount || 0), 0),
      avgRewardScore:      sessions.reduce((acc: number, s: any) => acc + (s.metrics?.averageRewardScore || 0), 0) / (sessions.length || 1),
      lastRun:             sessions[0]?.timestamp || null,
      sessions: sessions.map((s: any) => ({
        sessionId:        s.sessionId,
        timestamp:        s.timestamp,
        state:            s.state,
        sampledMinerCount: s.sampledMinerCount,
        avgRewardScore:   s.metrics?.averageRewardScore
      }))
    };

    res.json({ success: true, data: summary });
  } catch (error: any) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Network dashboard endpoints
app.get('/api/network/stats', readLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    const { window: tw = '24h' } = req.query;
    const since = new Date();
    if (tw === '7d')       since.setDate(since.getDate() - 7);
    else if (tw === '30d') since.setDate(since.getDate() - 30);
    else                   since.setHours(since.getHours() - 24);

    const latestSession = await ValidationSession
      .findOne({ 'subnetSnapshot.block': { $exists: true } })
      .sort({ timestamp: -1 }).lean();

    const snap = (latestSession as any)?.subnetSnapshot;

    const dailyAudits = await ValidationSession.countDocuments({
      state: 'completed', timestamp: { $gte: since }
    });

    const accAgg = await MinerHistory.aggregate([
      { $match: { timestamp: { $gte: since } } },
      { $group: { _id: null, avgAccuracy: { $avg: '$rewardScore' } } }
    ]);

    res.json({
      success: true,
      data: {
        activeValidators: snap?.activeValidators ?? 0,
        activeMiners:     snap?.activeMiners     ?? 0,
        dailyAudits,
        avgAccuracy: Number((accAgg[0]?.avgAccuracy ?? 0).toFixed(4))
      }
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/network/agents', readLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
    const { timeRange = '30d' } = req.query;

    const since = new Date();
    if (timeRange === '24h')     since.setHours(since.getHours() - 24);
    else if (timeRange === '7d') since.setDate(since.getDate() - 7);
    else                         since.setDate(since.getDate() - 30);

    const agentStats = await MinerHistory.aggregate([
      { $match: { timestamp: { $gte: since } } },
      {
        $group: {
          _id: '$minerUid',
          avgReward:          { $avg: '$rewardScore' },
          totalReward:        { $sum: '$rewardScore' },
          participationCount: { $sum: 1 },
          successCount:       { $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] } },
          latestSessionId:    { $last: '$sessionId' }
        }
      },
      { $sort: { avgReward: -1 } },
      { $limit: limit }
    ]);

    const sessionIds = agentStats.map((a: any) => a.latestSessionId).filter(Boolean);
    const sessions = await ValidationSession
      .find({ sessionId: { $in: sessionIds } }, { sessionId: 1, minerResponses: 1 })
      .lean();

    const sessionMap: Record<string, any> = {};
    for (const s of sessions) sessionMap[(s as any).sessionId] = s;

    const agents = agentStats.map((entry: any, idx: number) => {
      const sess     = sessionMap[entry.latestSessionId];
      const minerResp = sess?.minerResponses?.find((r: any) => r.minerUid === entry._id);
      const successRate = entry.participationCount > 0
        ? (entry.successCount / entry.participationCount) * 100 : 0;

      return {
        rank:      idx + 1,
        minerUid:  entry._id,
        agent:     minerResp?.githubUrl ?? null,
        benchmark: Number((entry.avgReward * 100).toFixed(2)),
        incentive: Number(entry.totalReward.toFixed(6)),
        emission:  entry.participationCount,
        consensus: Number(successRate.toFixed(2))
      };
    });

    res.json({ success: true, timeRange, data: agents });
  } catch (error: any) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/network/throughput', readLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    const { timeRange = '7d' } = req.query;
    const since = new Date();
    let bucketMs: number;

    if (timeRange === '24h') {
      since.setHours(since.getHours() - 24);
      bucketMs = 60 * 60 * 1000;
    } else if (timeRange === '30d') {
      since.setDate(since.getDate() - 30);
      bucketMs = 24 * 60 * 60 * 1000;
    } else {
      since.setDate(since.getDate() - 7);
      bucketMs = 6 * 60 * 60 * 1000;
    }

    const series = await ValidationSession.aggregate([
      { $match: { timestamp: { $gte: since }, state: 'completed' } },
      {
        $group: {
          _id: { $subtract: [{ $toLong: '$timestamp' }, { $mod: [{ $toLong: '$timestamp' }, bucketMs] }] },
          completedSessions: { $sum: 1 },
          avgRewardScore:    { $avg: '$metrics.averageRewardScore' }
        }
      },
      { $sort: { _id: 1 } },
      {
        $project: {
          _id: 0,
          timestamp:         { $toDate: '$_id' },
          completedSessions: 1,
          avgRewardScore:    { $ifNull: ['$avgRewardScore', 0] }
        }
      }
    ]);

    res.json({ success: true, timeRange, bucketMs, data: series });
  } catch (error: any) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/health', (_req: Request, res: Response): void => {
  res.json({ success: true, status: 'healthy', timestamp: new Date() });
});

// =====================
// ERROR HANDLING
// =====================

app.use((err: any, _req: Request, res: Response, _next: NextFunction): void => {
  // Don't leak error details in production
  const message = process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message;
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: message });
});

app.use((req: Request, res: Response): void => {
  res.status(404).json({ success: false, error: 'Endpoint not found' });
  // Note: path intentionally omitted — avoids reflecting arbitrary input back
});

// =====================
// DATABASE + STARTUP
// =====================

const connectDB = async (): Promise<void> => {
  try {
    await mongoose.connect(process.env.MONGO_URI!);
    console.log('✓ Connected to MongoDB');
  } catch (error) {
    console.error('✗ Failed to connect to MongoDB:', error);
    process.exit(1);
  }
};

const PORT = process.env.PORT || 5000;

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✓ Server running on port ${PORT} [${process.env.NODE_ENV || 'development'}]`);
  });
});

process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM received — shutting down');
  await mongoose.disconnect();
  process.exit(0);
});

export default app;