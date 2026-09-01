import cors from 'cors';
import bcrypt from 'bcryptjs';
import express from 'express';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import { Op, ValidationError } from 'sequelize';
import swaggerUi from 'swagger-ui-express';

import { openapi } from './openapi.js';
import { buildRecommendations } from './services/recommendations.js';
import { buildExecutiveReport } from './services/report.js';
import { calculateRisk, normalizeNistFunction } from './services/risk.js';

const asyncHandler = (handler) => (request, response, next) => Promise.resolve(handler(request, response, next)).catch(next);
const notFound = (message) => Object.assign(new Error(message), { status: 404 });

function riskJson(risk) {
  const data = risk.toJSON();
  return { ...data, asset_name: data.asset?.name, asset: undefined };
}

function assetPayload(body) {
  return {
    name: body.name,
    asset_type: body.asset_type,
    owner: body.owner,
    location: body.location,
    criticality: body.criticality ?? 3,
    status: body.status ?? 'Activo',
    description: body.description ?? null,
  };
}

function riskPayload(body) {
  const calculated = calculateRisk(body.likelihood, body.impact);
  return {
    title: body.title,
    threat: body.threat,
    ...calculated,
    status: body.status ?? 'Abierto',
    nist_function: normalizeNistFunction(body.nist_function),
    notes: body.notes ?? null,
    asset_id: Number(body.asset_id),
  };
}

export function createApp({ models, database }) {
  const { User, Asset, RiskAssessment } = models;
  const app = express();
  const allowedOrigins = (process.env.CORS_ORIGINS ?? 'http://localhost:3000').split(',').map((value) => value.trim());

  app.disable('x-powered-by');
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors({ origin: allowedOrigins, credentials: true }));
  app.use(express.json({ limit: '1mb' }));
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(openapi, { customSiteTitle: 'CiberGuate IA API' }));

  app.get('/health', asyncHandler(async (_request, response) => {
    await database.authenticate();
    response.json({ status: 'healthy' });
  }));

  app.post('/api/v1/auth/login', asyncHandler(async (request, response) => {
    const email = String(request.body.email ?? '').trim().toLowerCase();
    const password = String(request.body.password ?? '');
    const user = email ? await User.findOne({ where: { email } }) : null;
    if (!user || !await bcrypt.compare(password, user.password_hash)) {
      return response.status(401).json({ detail: 'Correo o contraseña incorrectos' });
    }
    const signingKey = process.env.JWT_SECRET;
    if (!signingKey) throw new Error('JWT_SECRET no está configurado');
    const token = jwt.sign({ sub: String(user.id), email: user.email, role: user.role }, signingKey, { expiresIn: '8h', issuer: 'ciberguate-api', audience: 'ciberguate-web' });
    return response.json({ access_token: token, token_type: 'Bearer', expires_in: 28800, user: { email: user.email, display_name: user.display_name, role: user.role } });
  }));

  app.use('/api/v1', asyncHandler(async (request, response, next) => {
    const token = request.headers.authorization?.match(/^Bearer (.+)$/i)?.[1];
    try {
      const payload = jwt.verify(token ?? '', process.env.JWT_SECRET ?? '', { issuer: 'ciberguate-api', audience: 'ciberguate-web' });
      request.user = payload;
      next();
    } catch {
      response.status(401).json({ detail: 'Autenticación requerida' });
    }
  }));

  app.get('/api/v1/auth/me', asyncHandler(async (request, response) => {
    const user = await User.findByPk(request.user.sub, { attributes: ['email', 'display_name', 'role'] });
    if (!user) return response.status(401).json({ detail: 'Usuario no disponible' });
    return response.json(user);
  }));

  app.get('/api/v1/assets', asyncHandler(async (_request, response) => {
    response.json(await Asset.findAll({ order: [['createdAt', 'DESC']] }));
  }));
  app.post('/api/v1/assets', asyncHandler(async (request, response) => {
    response.status(201).json(await Asset.create(assetPayload(request.body)));
  }));
  app.get('/api/v1/assets/:id', asyncHandler(async (request, response) => {
    const asset = await Asset.findByPk(request.params.id);
    if (!asset) throw notFound('Activo no encontrado');
    response.json(asset);
  }));
  app.put('/api/v1/assets/:id', asyncHandler(async (request, response) => {
    const asset = await Asset.findByPk(request.params.id);
    if (!asset) throw notFound('Activo no encontrado');
    response.json(await asset.update(assetPayload(request.body)));
  }));
  app.delete('/api/v1/assets/:id', asyncHandler(async (request, response) => {
    const asset = await Asset.findByPk(request.params.id);
    if (!asset) throw notFound('Activo no encontrado');
    await asset.destroy();
    response.status(204).end();
  }));

  app.get('/api/v1/risks', asyncHandler(async (_request, response) => {
    const risks = await RiskAssessment.findAll({ include: [{ model: Asset, as: 'asset', attributes: ['name'] }], order: [['score', 'DESC']] });
    response.json(risks.map(riskJson));
  }));
  app.post('/api/v1/risks', asyncHandler(async (request, response) => {
    const payload = riskPayload(request.body);
    if (!await Asset.findByPk(payload.asset_id)) throw notFound('Activo no encontrado');
    const created = await RiskAssessment.create(payload);
    const risk = await RiskAssessment.findByPk(created.id, { include: [{ model: Asset, as: 'asset', attributes: ['name'] }] });
    response.status(201).json(riskJson(risk));
  }));
  app.get('/api/v1/risks/:id', asyncHandler(async (request, response) => {
    const risk = await RiskAssessment.findByPk(request.params.id, { include: [{ model: Asset, as: 'asset', attributes: ['name'] }] });
    if (!risk) throw notFound('Riesgo no encontrado');
    response.json(riskJson(risk));
  }));
  app.put('/api/v1/risks/:id', asyncHandler(async (request, response) => {
    const risk = await RiskAssessment.findByPk(request.params.id);
    if (!risk) throw notFound('Riesgo no encontrado');
    const payload = riskPayload(request.body);
    if (!await Asset.findByPk(payload.asset_id)) throw notFound('Activo no encontrado');
    await risk.update(payload);
    const updated = await RiskAssessment.findByPk(risk.id, { include: [{ model: Asset, as: 'asset', attributes: ['name'] }] });
    response.json(riskJson(updated));
  }));
  app.delete('/api/v1/risks/:id', asyncHandler(async (request, response) => {
    const risk = await RiskAssessment.findByPk(request.params.id);
    if (!risk) throw notFound('Riesgo no encontrado');
    await risk.destroy();
    response.status(204).end();
  }));

  app.get('/api/v1/dashboard', asyncHandler(async (_request, response) => {
    const [totalAssets, criticalAssets, risks] = await Promise.all([
      Asset.count(), Asset.count({ where: { criticality: { [Op.gte]: 4 } } }), RiskAssessment.findAll(),
    ]);
    const openRisks = risks.filter((risk) => !['Mitigado', 'Cerrado'].includes(risk.status));
    const risksByLevel = Object.fromEntries(['Crítico', 'Alto', 'Medio', 'Bajo'].map((level) => [level, openRisks.filter((risk) => risk.level === level).length]));
    const average = risks.length ? risks.reduce((sum, risk) => sum + risk.score, 0) / risks.length : 0;
    const exposure = openRisks.length ? openRisks.reduce((sum, risk) => sum + risk.score, 0) / openRisks.length : 0;
    response.json({ total_assets: totalAssets, critical_assets: criticalAssets, open_risks: openRisks.length, critical_risks: risksByLevel['Crítico'], average_risk_score: Number(average.toFixed(1)), compliance_percentage: Math.max(0, Math.min(100, Math.round(100 - exposure * 2.3))), risks_by_level: risksByLevel });
  }));

  app.get('/api/v1/recommendations', asyncHandler(async (_request, response) => {
    const risks = await RiskAssessment.findAll({ where: { status: { [Op.notIn]: ['Mitigado', 'Cerrado'] } } });
    response.json(buildRecommendations(risks));
  }));
  app.get('/api/v1/reports/executive.pdf', asyncHandler(async (_request, response) => {
    const [assets, risks] = await Promise.all([Asset.findAll(), RiskAssessment.findAll({ include: [{ model: Asset, as: 'asset', attributes: ['name'] }] })]);
    const report = await buildExecutiveReport(assets, risks, buildRecommendations(risks));
    response.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="informe-ejecutivo-riesgos.pdf"', 'Content-Length': report.length });
    response.send(report);
  }));

  app.use((_request, response) => response.status(404).json({ detail: 'Ruta no encontrada' }));
  app.use((error, _request, response, _next) => {
    const validationError = error instanceof ValidationError;
    const status = error.status ?? (validationError ? 400 : 500);
    if (status >= 500) console.error(error);
    response.status(status).json({ detail: validationError ? error.errors.map((item) => item.message).join(', ') : error.message });
  });
  return app;
}
