import express, { Request, Response, NextFunction, Express } from 'express';
import mongoose, { Schema, Document, Model } from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';

dotenv.config();

const app: Express = express();

// =====================
// MIDDLEWARE
// =====================

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
  });
  next();
});

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

interface GroundTruth {
  reportId: string;
  vulnerabilities: string[];
  criticalIssues?: number;
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
  groundTruth: GroundTruth;
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

  // Miner sampling
  sampledMinerCount: Number,
  sampledMinerUids: [Number],

  // Challenge info
  challengeInfo: {
    projectId: String,
    description: String,
    difficulty: String,
    createdAt: Date,
    rawData: Schema.Types.Mixed
  },

  // Ground truth
  groundTruth: {
    reportId: String,
    vulnerabilities: [String],
    criticalIssues: Number,
    rawData: Schema.Types.Mixed
  },

  // Miner responses and rewards
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

  // Computation results
  computedRewards: [{
    minerUid: Number,
    score: Number,
    timestamp: Date,
    _id: false
  }],

  // Summary metrics
  metrics: {
    totalQueryTime: Number,
    averageRewardScore: Number,
    successRate: Number,
    failureCount: Number,
    validFindings: Number
  },

  // Subnet state snapshot
  subnetSnapshot: {
    netuid: Number,
    block: Number,
    activeValidators: Number,
    activeMiners: Number,
    totalStake: Number,
    emissionPerBlock: Number,
    timestamp: Date
  },

  // Error tracking
  validationErrors: [{
    stage: String,
    message: String,
    timestamp: Date,
    stackTrace: String,
    _id: false
  }],

  // Additional metadata
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

// Create indexes for performance
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

// =====================
// API ENDPOINTS
// =====================

/**
 * POST /api/validation/start
 * Start a new validation session
 */
app.post('/api/validation/start', async (req: Request, res: Response): Promise<void> => {
  try {
    const {
      sampledMinerCount,
      sampledMinerUids,
      validatorAddress,
      configVersion
    } = req.body;

    if (!sampledMinerUids || !Array.isArray(sampledMinerUids)) {
      res.status(400).json({
        success: false,
        error: 'sampledMinerUids must be an array'
      });
      return;
    }

    const sessionId = uuidv4();

    const session = new ValidationSession({
      sessionId,
      sampledMinerCount: sampledMinerCount || sampledMinerUids.length,
      sampledMinerUids,
      state: 'pending',
      metadata: {
        validatorAddress,
        configVersion
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
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * POST /api/validation/:sessionId/challenge
 * Record fetched challenge data
 */
app.post('/api/validation/:sessionId/challenge', async (req: Request, res: Response): Promise<void> => {
  try {
    const { sessionId } = req.params;
    const { projectId, description, difficulty, rawData } = req.body;

    if (!projectId) {
      res.status(400).json({
        success: false,
        error: 'projectId is required'
      });
      return;
    }

    const session = await ValidationSession.findOneAndUpdate(
      { sessionId },
      {
        $set: {
          state: 'in-progress',
          projectId,
          'challengeInfo.projectId': projectId,
          'challengeInfo.description': description,
          'challengeInfo.difficulty': difficulty,
          'challengeInfo.rawData': rawData,
          'challengeInfo.createdAt': new Date()
        }
      },
      { new: true }
    );

    if (!session) {
      res.status(404).json({ success: false, error: 'Session not found' });
      return;
    }

    res.json({
      success: true,
      message: 'Challenge recorded',
      projectId
    });
  } catch (error: any) {
    console.error('Error in POST /api/validation/:sessionId/challenge:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * POST /api/validation/:sessionId/ground-truth
 * Record ground truth data
 */
app.post('/api/validation/:sessionId/ground-truth', async (req: Request, res: Response): Promise<void> => {
  try {
    const { sessionId } = req.params;
    const { reportId, vulnerabilities, criticalIssues, rawData } = req.body;

    const session = await ValidationSession.findOneAndUpdate(
      { sessionId },
      {
        $set: {
          'groundTruth.reportId': reportId,
          'groundTruth.vulnerabilities': vulnerabilities || [],
          'groundTruth.criticalIssues': criticalIssues,
          'groundTruth.rawData': rawData
        }
      },
      { new: true }
    );

    if (!session) {
      res.status(404).json({ success: false, error: 'Session not found' });
      return;
    }

    res.json({
      success: true,
      message: 'Ground truth recorded'
    });
  } catch (error: any) {
    console.error('Error in POST /api/validation/:sessionId/ground-truth:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * POST /api/validation/:sessionId/miner-response
 * Record individual miner response
 */
app.post('/api/validation/:sessionId/miner-response', async (req: Request, res: Response): Promise<void> => {
  try {
    const { sessionId } = req.params;
    const {
      minerUid,
      githubUrl,
      responseTime,
      success,
      errorMessage,
      agentPerformance
    } = req.body;

    if (typeof minerUid !== 'number') {
      res.status(400).json({
        success: false,
        error: 'minerUid must be a number'
      });
      return;
    }

    const session = await ValidationSession.findOneAndUpdate(
      { sessionId },
      {
        $push: {
          minerResponses: {
            minerUid,
            githubUrl,
            responseTime,
            success,
            errorMessage,
            timestamp: new Date(),
            agentPerformance: agentPerformance || {}
          }
        }
      },
      { new: true }
    );

    if (!session) {
      res.status(404).json({ success: false, error: 'Session not found' });
      return;
    }

    res.json({
      success: true,
      message: 'Miner response recorded',
      minerUid
    });
  } catch (error: any) {
    console.error('Error in POST /api/validation/:sessionId/miner-response:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * POST /api/validation/:sessionId/miner-reward
 * Record reward computation for a miner
 */
app.post('/api/validation/:sessionId/miner-reward', async (req: Request, res: Response): Promise<void> => {
  try {
    const { sessionId } = req.params;
    const { minerUid, rewardScore, rewardReason } = req.body;

    if (typeof minerUid !== 'number') {
      res.status(400).json({
        success: false,
        error: 'minerUid must be a number'
      });
      return;
    }

    // Update validation session
    const session = await ValidationSession.findOneAndUpdate(
      { sessionId, 'minerResponses.minerUid': minerUid },
      {
        $set: {
          'minerResponses.$.rewardScore': rewardScore,
          'minerResponses.$.rewardReason': rewardReason
        }
      },
      { new: true }
    );

    if (!session) {
      res.status(404).json({
        success: false,
        error: 'Session or miner response not found'
      });
      return;
    }

    // Also record in miner history
    await MinerHistory.create({
      minerUid,
      sessionId,
      rewardScore,
      timestamp: new Date(),
      status: rewardScore > 0 ? 'success' : 'failed'
    });

    res.json({
      success: true,
      message: 'Reward recorded',
      minerUid,
      rewardScore
    });
  } catch (error: any) {
    console.error('Error in POST /api/validation/:sessionId/miner-reward:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * POST /api/validation/:sessionId/rewards-update
 * Record batch reward updates
 */
app.post('/api/validation/:sessionId/rewards-update', async (req: Request, res: Response): Promise<void> => {
  try {
    const { sessionId } = req.params;
    const { minerUids, rewards } = req.body;

    if (!Array.isArray(minerUids) || !Array.isArray(rewards)) {
      res.status(400).json({
        success: false,
        error: 'minerUids and rewards must be arrays'
      });
      return;
    }

    if (minerUids.length !== rewards.length) {
      res.status(400).json({
        success: false,
        error: 'minerUids and rewards must have the same length'
      });
      return;
    }

    const updateId = uuidv4();

    // Create reward update record
    await RewardUpdate.create({
      updateId,
      sessionId,
      minerUids,
      rewards
    });

    // Update all miner rewards in session
    const session = await ValidationSession.findOne({ sessionId });
    if (session) {
      session.computedRewards = minerUids.map((uid: number, idx: number) => ({
        minerUid: uid,
        score: rewards[idx],
        timestamp: new Date()
      }));

      // Calculate metrics
      const successCount = rewards.filter((r: number) => r > 0).length;
      session.metrics = {
        successRate: (successCount / minerUids.length) * 100,
        averageRewardScore: rewards.reduce((a: number, b: number) => a + b, 0) / minerUids.length,
        failureCount: minerUids.length - successCount
      };

      await session.save();
    }

    res.json({
      success: true,
      message: 'Rewards updated',
      updateId,
      minerCount: minerUids.length
    });
  } catch (error: any) {
    console.error('Error in POST /api/validation/:sessionId/rewards-update:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * POST /api/validation/:sessionId/subnet-snapshot
 * Record subnet state snapshot
 */
app.post('/api/validation/:sessionId/subnet-snapshot', async (req: Request, res: Response): Promise<void> => {
  try {
    const { sessionId } = req.params;
    const {
      netuid,
      block,
      activeValidators,
      activeMiners,
      totalStake,
      emissionPerBlock
    } = req.body;

    if (typeof netuid !== 'number' || typeof block !== 'number') {
      res.status(400).json({
        success: false,
        error: 'netuid and block must be numbers'
      });
      return;
    }

    await ValidationSession.findOneAndUpdate(
      { sessionId },
      {
        $set: {
          'subnetSnapshot.netuid': netuid,
          'subnetSnapshot.block': block,
          'subnetSnapshot.activeValidators': activeValidators,
          'subnetSnapshot.activeMiners': activeMiners,
          'subnetSnapshot.totalStake': totalStake,
          'subnetSnapshot.emissionPerBlock': emissionPerBlock,
          'subnetSnapshot.timestamp': new Date()
        }
      }
    );

    res.json({
      success: true,
      message: 'Subnet snapshot recorded'
    });
  } catch (error: any) {
    console.error('Error in POST /api/validation/:sessionId/subnet-snapshot:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * POST /api/validation/:sessionId/error
 * Log validation error
 */
app.post('/api/validation/:sessionId/error', async (req: Request, res: Response): Promise<void> => {
  try {
    const { sessionId } = req.params;
    const { stage, message, stackTrace } = req.body;

    if (!stage || !message) {
      res.status(400).json({
        success: false,
        error: 'stage and message are required'
      });
      return;
    }

    await ValidationSession.findOneAndUpdate(
      { sessionId },
      {
        $push: {
          validationErrors: {
            stage,
            message,
            timestamp: new Date(),
            stackTrace
          }
        }
      }
    );

    res.json({
      success: true,
      message: 'Error logged'
    });
  } catch (error: any) {
    console.error('Error in POST /api/validation/:sessionId/error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * POST /api/validation/:sessionId/complete
 * Mark validation session as complete
 */
app.post('/api/validation/:sessionId/complete', async (req: Request, res: Response): Promise<void> => {
  try {
    const { sessionId } = req.params;
    const { metrics } = req.body;

    const session = await ValidationSession.findOneAndUpdate(
      { sessionId },
      {
        $set: {
          state: 'completed',
          'metrics.totalQueryTime': metrics?.totalQueryTime,
          'metrics.averageRewardScore': metrics?.averageRewardScore,
          'metrics.successRate': metrics?.successRate,
          'metrics.failureCount': metrics?.failureCount,
          'metrics.validFindings': metrics?.validFindings
        }
      },
      { new: true }
    );

    if (!session) {
      res.status(404).json({ success: false, error: 'Session not found' });
      return;
    }

    res.json({
      success: true,
      message: 'Validation session completed',
      sessionId
    });
  } catch (error: any) {
    console.error('Error in POST /api/validation/:sessionId/complete:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * GET /api/validation/:sessionId
 * Get full validation session details
 */
app.get('/api/validation/:sessionId', async (req: Request, res: Response): Promise<void> => {
  try {
    const { sessionId } = req.params;

    const session = await ValidationSession.findOne({ sessionId });

    if (!session) {
      res.status(404).json({ success: false, error: 'Session not found' });
      return;
    }

    res.json({
      success: true,
      data: session
    });
  } catch (error: any) {
    console.error('Error in GET /api/validation/:sessionId:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * GET /api/validation/sessions/recent
 * Get recent validation sessions
 */
app.get('/api/validation/sessions/recent', async (req: Request, res: Response): Promise<void> => {
  try {
    const { limit = '20', skip = '0' } = req.query;

    const sessions = await ValidationSession.find()
      .sort({ timestamp: -1 })
      .limit(parseInt(limit as string))
      .skip(parseInt(skip as string));

    const total = await ValidationSession.countDocuments();

    res.json({
      success: true,
      data: sessions,
      pagination: {
        total,
        limit: parseInt(limit as string),
        skip: parseInt(skip as string)
      }
    });
  } catch (error: any) {
    console.error('Error in GET /api/validation/sessions/recent:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * GET /api/validation/sessions/stats
 * Get validation statistics
 */
app.get('/api/validation/sessions/stats', async (req: Request, res: Response): Promise<void> => {
  try {
    const { timeRange = '24h' } = req.query;

    let startDate = new Date();
    if (timeRange === '24h') startDate.setHours(startDate.getHours() - 24);
    else if (timeRange === '7d') startDate.setDate(startDate.getDate() - 7);
    else if (timeRange === '30d') startDate.setDate(startDate.getDate() - 30);

    const stats = await ValidationSession.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: null,
          totalSessions: { $sum: 1 },
          completedSessions: {
            $sum: { $cond: [{ $eq: ['$state', 'completed'] }, 1, 0] }
          },
          failedSessions: {
            $sum: { $cond: [{ $eq: ['$state', 'failed'] }, 1, 0] }
          },
          avgRewardScore: { $avg: '$metrics.averageRewardScore' },
          totalMinersQueried: { $sum: '$sampledMinerCount' },
          avgQueryTime: { $avg: '$metrics.totalQueryTime' }
        }
      }
    ]);

    res.json({
      success: true,
      timeRange,
      data: stats[0] || {
        totalSessions: 0,
        completedSessions: 0,
        failedSessions: 0,
        avgRewardScore: 0,
        totalMinersQueried: 0,
        avgQueryTime: 0
      }
    });
  } catch (error: any) {
    console.error('Error in GET /api/validation/sessions/stats:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * GET /api/miners/:minerUid/history
 * Get miner performance history
 */
app.get('/api/miners/:minerUid/history', async (req: Request, res: Response): Promise<void> => {
  try {
    const { minerUid } = req.params;
    const { limit = '50' } = req.query;

    const minerIdNum = parseInt(minerUid);

    const history = await MinerHistory.find({ minerUid: minerIdNum })
      .sort({ timestamp: -1 })
      .limit(parseInt(limit as string));

    const stats = await MinerHistory.aggregate([
      { $match: { minerUid: minerIdNum } },
      {
        $group: {
          _id: null,
          avgReward: { $avg: '$rewardScore' },
          totalParticipations: { $sum: 1 },
          successCount: {
            $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
          },
          failureCount: {
            $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
          },
          avgAccuracy: { $avg: '$accuracy' }
        }
      }
    ]);

    res.json({
      success: true,
      minerUid: minerIdNum,
      history,
      stats: stats[0] || {
        avgReward: 0,
        totalParticipations: 0,
        successCount: 0,
        failureCount: 0,
        avgAccuracy: 0
      }
    });
  } catch (error: any) {
    console.error('Error in GET /api/miners/:minerUid/history:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * GET /api/leaderboard
 * Get top performing miners
 */
app.get('/api/leaderboard', async (req: Request, res: Response): Promise<void> => {
  try {
    const { limit = '100', timeRange = '30d' } = req.query;

    let startDate = new Date();
    if (timeRange === '24h') startDate.setHours(startDate.getHours() - 24);
    else if (timeRange === '7d') startDate.setDate(startDate.getDate() - 7);
    else if (timeRange === '30d') startDate.setDate(startDate.getDate() - 30);

    const leaderboard = await MinerHistory.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$minerUid',
          totalRewards: { $sum: '$rewardScore' },
          avgReward: { $avg: '$rewardScore' },
          participationCount: { $sum: 1 },
          successCount: {
            $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
          },
          avgAccuracy: { $avg: '$accuracy' }
        }
      },
      {
        $sort: { totalRewards: -1 }
      },
      {
        $limit: parseInt(limit as string)
      }
    ]);

    res.json({
      success: true,
      timeRange,
      leaderboard: leaderboard.map((entry: any, idx: number) => ({
        rank: idx + 1,
        minerUid: entry._id,
        totalRewards: entry.totalRewards,
        avgReward: Number(entry.avgReward?.toFixed(4)) || 0,
        participationCount: entry.participationCount,
        successRate: Number(((entry.successCount / entry.participationCount) * 100).toFixed(2)) + '%',
        avgAccuracy: entry.avgAccuracy?.toFixed(4) || 'N/A'
      }))
    });
  } catch (error: any) {
    console.error('Error in GET /api/leaderboard:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * GET /api/project/:projectId/summary
 * Get project validation summary
 */
app.get('/api/project/:projectId/summary', async (req: Request, res: Response): Promise<void> => {
  try {
    const { projectId } = req.params;

    const sessions = await ValidationSession.find({ projectId })
      .sort({ timestamp: -1 });

    const summary = {
      projectId,
      totalValidationRuns: sessions.length,
      successfulRuns: sessions.filter((s: any) => s.state === 'completed').length,
      failedRuns: sessions.filter((s: any) => s.state === 'failed').length,
      totalMinersQueried: sessions.reduce((acc: number, s: any) => acc + (s.sampledMinerCount || 0), 0),
      avgRewardScore: sessions.reduce((acc: number, s: any) => acc + (s.metrics?.averageRewardScore || 0), 0) / sessions.length,
      lastRun: sessions[0]?.timestamp || null,
      sessions: sessions.map((s: any) => ({
        sessionId: s.sessionId,
        timestamp: s.timestamp,
        state: s.state,
        sampledMinerCount: s.sampledMinerCount,
        avgRewardScore: s.metrics?.averageRewardScore
      }))
    };

    res.json({
      success: true,
      data: summary
    });
  } catch (error: any) {
    console.error('Error in GET /api/project/:projectId/summary:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

/**
 * GET /api/health
 * Health check endpoint
 */
app.get('/api/health', (_req: Request, res: Response): void => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date()
  });
});

/**
 * GET /api/docs
 * API documentation
 */
app.get('/api/docs', (_req: Request, res: Response): void => {
  const docs = {
    title: 'Subnet Validator Backend API',
    version: '1.0.0',
    baseUrl: process.env.BASE_URL || 'http://localhost:5000',
    endpoints: [
      {
        method: 'POST',
        path: '/api/validation/start',
        description: 'Start a new validation session',
        body: {
          sampledMinerCount: 'number',
          sampledMinerUids: 'number[]',
          validatorAddress: 'string (optional)',
          configVersion: 'string (optional)'
        }
      },
      {
        method: 'POST',
        path: '/api/validation/:sessionId/challenge',
        description: 'Record fetched challenge data',
        body: {
          projectId: 'string',
          description: 'string (optional)',
          difficulty: 'string (optional)',
          rawData: 'object (optional)'
        }
      },
      {
        method: 'POST',
        path: '/api/validation/:sessionId/ground-truth',
        description: 'Record ground truth data',
        body: {
          reportId: 'string',
          vulnerabilities: 'string[]',
          criticalIssues: 'number (optional)',
          rawData: 'object (optional)'
        }
      },
      {
        method: 'POST',
        path: '/api/validation/:sessionId/miner-response',
        description: 'Record individual miner response',
        body: {
          minerUid: 'number',
          githubUrl: 'string (optional)',
          responseTime: 'number',
          success: 'boolean',
          errorMessage: 'string (optional)',
          agentPerformance: 'object (optional)'
        }
      },
      {
        method: 'POST',
        path: '/api/validation/:sessionId/miner-reward',
        description: 'Record reward computation for a miner',
        body: {
          minerUid: 'number',
          rewardScore: 'number',
          rewardReason: 'string (optional)'
        }
      },
      {
        method: 'POST',
        path: '/api/validation/:sessionId/rewards-update',
        description: 'Record batch reward updates',
        body: {
          minerUids: 'number[]',
          rewards: 'number[]'
        }
      },
      {
        method: 'POST',
        path: '/api/validation/:sessionId/subnet-snapshot',
        description: 'Record subnet state snapshot',
        body: {
          netuid: 'number',
          block: 'number',
          activeValidators: 'number',
          activeMiners: 'number',
          totalStake: 'number',
          emissionPerBlock: 'number'
        }
      },
      {
        method: 'POST',
        path: '/api/validation/:sessionId/error',
        description: 'Log validation error',
        body: {
          stage: 'string',
          message: 'string',
          stackTrace: 'string (optional)'
        }
      },
      {
        method: 'POST',
        path: '/api/validation/:sessionId/complete',
        description: 'Mark validation session as complete',
        body: {
          metrics: 'object (optional)'
        }
      },
      {
        method: 'GET',
        path: '/api/validation/:sessionId',
        description: 'Get full validation session details'
      },
      {
        method: 'GET',
        path: '/api/validation/sessions/recent',
        description: 'Get recent validation sessions',
        query: {
          limit: 'number (default: 20)',
          skip: 'number (default: 0)'
        }
      },
      {
        method: 'GET',
        path: '/api/validation/sessions/stats',
        description: 'Get validation statistics',
        query: {
          timeRange: 'string (24h|7d|30d, default: 24h)'
        }
      },
      {
        method: 'GET',
        path: '/api/miners/:minerUid/history',
        description: 'Get miner performance history',
        query: {
          limit: 'number (default: 50)'
        }
      },
      {
        method: 'GET',
        path: '/api/leaderboard',
        description: 'Get top performing miners',
        query: {
          limit: 'number (default: 100)',
          timeRange: 'string (24h|7d|30d, default: 30d)'
        }
      },
      {
        method: 'GET',
        path: '/api/project/:projectId/summary',
        description: 'Get project validation summary'
      },
      {
        method: 'GET',
        path: '/api/health',
        description: 'Health check endpoint'
      }
    ]
  };

  res.json(docs);
});

// =====================
// ERROR HANDLING
// =====================

app.use((err: any, _req: Request, res: Response, _next: NextFunction): void => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

// 404 handler
app.use((req: Request, res: Response): void => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.path
  });
});

// =====================
// DATABASE CONNECTION
// =====================

const connectDB = async (): Promise<void> => {
  try {
    const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/subnet-validator';
    await mongoose.connect(mongoUri);
    console.log('✓ Connected to MongoDB');
  } catch (error) {
    console.error('✗ Failed to connect to MongoDB:', error);
    process.exit(1);
  }
};

// =====================
// SERVER STARTUP
// =====================

const PORT = process.env.PORT || 5000;

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║     Subnet Validator Backend - Running                    ║
╚════════════════════════════════════════════════════════════╝

📊 Server Information:
   ➜ Port: ${PORT}
   ➜ Environment: ${process.env.NODE_ENV || 'development'}
   ➜ MongoDB: ${process.env.MONGO_URI || 'mongodb://localhost:27017/subnet-validator'}

📚 API Documentation:
   ➜ Available at: http://localhost:${PORT}/api/docs

🔗 Core Endpoints:
   POST   /api/validation/start
   POST   /api/validation/:sessionId/challenge
   POST   /api/validation/:sessionId/ground-truth
   POST   /api/validation/:sessionId/miner-response
   POST   /api/validation/:sessionId/miner-reward
   POST   /api/validation/:sessionId/rewards-update
   POST   /api/validation/:sessionId/subnet-snapshot
   POST   /api/validation/:sessionId/error
   POST   /api/validation/:sessionId/complete
   GET    /api/validation/:sessionId
   GET    /api/validation/sessions/recent
   GET    /api/validation/sessions/stats
   GET    /api/miners/:minerUid/history
   GET    /api/leaderboard
   GET    /api/project/:projectId/summary
   GET    /api/health
   GET    /api/docs

✓ Backend is ready to accept requests!
    `);
  });
});

process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received: closing HTTP server');
  await mongoose.disconnect();
  process.exit(0);
});

export default app;