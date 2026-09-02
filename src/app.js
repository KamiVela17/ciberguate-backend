import cors from 'cors';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import express from 'express';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import { Op, ValidationError } from 'sequelize';
import swaggerUi from 'swagger-ui-express';

import { openapi } from './openapi.js';
import { buildRecommendations } from './services/recommendations.js';
import { buildExecutiveReport, collectExecutiveReportData } from './services/report.js';
import { calculateRisk, normalizeNistFunction } from './services/risk.js';
import { createTotpSecret, totpUri, verifyTotp } from './services/totp.js';
import { registerPlatformRoutes } from './platform.js';

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
  const { User, Asset, RiskAssessment, MfaSetting, AuditLog } = models;
  const app = express();
  const recordAudit = (request, action, resource, metadata = {}) => AuditLog.create({ actor: request.user?.email ?? request.body?.email ?? 'sistema', action, resource, ip_address: request.ip, metadata });
  const allowedOrigins = (process.env.CORS_ORIGINS ?? 'http://localhost:3000').split(',').map((value) => value.trim());

  app.disable('x-powered-by');
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors({ origin: allowedOrigins, credentials: true }));
  app.use(express.json({ limit: '1mb' }));
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(openapi, { customSiteTitle: 'CiberGuate IA API' }));
  app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(openapi, { customSiteTitle: 'CiberGuate IA API' }));
  app.get('/api/openapi.json', (_request, response) => response.json(openapi));

  app.get('/health', asyncHandler(async (_request, response) => {
    await database.authenticate();
    response.json({ status: 'healthy' });
  }));

  const signAccessToken = (user) => jwt.sign({ sub: String(user.id), email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '8h', issuer: 'ciberguate-api', audience: 'ciberguate-web' });

  app.post('/api/v1/auth/login', asyncHandler(async (request, response) => {
    const email = String(request.body.email ?? '').trim().toLowerCase();
    const password = String(request.body.password ?? '');
    const user = email ? await User.findOne({ where: { email }, include: [{ model: MfaSetting, as: 'mfa', required: false }] }) : null;
    if (!user || !await bcrypt.compare(password, user.password_hash)) {
      return response.status(401).json({ detail: 'Correo o contraseña incorrectos' });
    }
    const signingKey = process.env.JWT_SECRET;
    if (!signingKey) throw new Error('JWT_SECRET no está configurado');
    if (user.mfa?.enabled) {
      const mfaToken = jwt.sign({ sub: String(user.id), purpose: 'mfa-login' }, signingKey, { expiresIn: '5m', issuer: 'ciberguate-api', audience: 'ciberguate-mfa' });
      return response.json({ mfa_required: true, mfa_token: mfaToken });
    }
    const token = signAccessToken(user);
    return response.json({ access_token: token, token_type: 'Bearer', expires_in: 28800, user: { email: user.email, display_name: user.display_name, role: user.role } });
  }));

  app.post('/api/v1/auth/mfa/verify-login', asyncHandler(async (request, response) => {
    let payload;
    try { payload = jwt.verify(request.body.mfa_token ?? '', process.env.JWT_SECRET ?? '', { issuer: 'ciberguate-api', audience: 'ciberguate-mfa' }); } catch { return response.status(401).json({ detail: 'Desafío MFA inválido o vencido' }); }
    if (payload.purpose !== 'mfa-login') return response.status(401).json({ detail: 'Desafío MFA inválido' });
    const user = await User.findByPk(payload.sub, { include: [{ model: MfaSetting, as: 'mfa', required: true }] });
    if (!user || !verifyTotp(user.mfa.secret, request.body.code)) return response.status(401).json({ detail: 'Código MFA incorrecto' });
    return response.json({ access_token: signAccessToken(user), token_type: 'Bearer', expires_in: 28800, user: { email: user.email, display_name: user.display_name, role: user.role } });
  }));

  app.get('/api/v1/auth/oauth/config', asyncHandler(async (_request, response) => {
    if (!process.env.OIDC_ISSUER || !process.env.OIDC_CLIENT_ID || !process.env.OIDC_REDIRECT_URI) return response.json({ enabled: false });
    const discovery = await fetch(`${process.env.OIDC_ISSUER.replace(/\/$/, '')}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(10000) }).then((result) => result.json());
    const state = jwt.sign({ purpose: 'oidc-login', nonce: crypto.randomBytes(16).toString('hex') }, process.env.JWT_SECRET, { expiresIn: '10m', issuer: 'ciberguate-api', audience: 'ciberguate-oidc' });
    const authorization = new URL(discovery.authorization_endpoint);
    authorization.search = new URLSearchParams({ client_id: process.env.OIDC_CLIENT_ID, redirect_uri: process.env.OIDC_REDIRECT_URI, response_type: 'code', scope: 'openid email profile', state }).toString();
    response.json({ enabled: true, authorization_url: authorization.toString() });
  }));

  app.post('/api/v1/auth/oauth/callback', asyncHandler(async (request, response) => {
    try { jwt.verify(request.body.state ?? '', process.env.JWT_SECRET ?? '', { issuer: 'ciberguate-api', audience: 'ciberguate-oidc' }); } catch { return response.status(401).json({ detail: 'Estado OAuth2 inválido o vencido' }); }
    const discovery = await fetch(`${process.env.OIDC_ISSUER.replace(/\/$/, '')}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(10000) }).then((result) => result.json());
    const tokenResponse = await fetch(discovery.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: request.body.code, client_id: process.env.OIDC_CLIENT_ID, client_secret: process.env.OIDC_CLIENT_SECRET ?? '', redirect_uri: process.env.OIDC_REDIRECT_URI }), signal: AbortSignal.timeout(15000) });
    if (!tokenResponse.ok) return response.status(401).json({ detail: 'El proveedor OAuth2 rechazó el código' });
    const tokens = await tokenResponse.json();
    const profile = await fetch(discovery.userinfo_endpoint, { headers: { Authorization: `Bearer ${tokens.access_token}` }, signal: AbortSignal.timeout(10000) }).then((result) => result.json());
    if (!profile.email) return response.status(400).json({ detail: 'El proveedor no entregó un correo electrónico' });
    const [user] = await User.findOrCreate({ where: { email: String(profile.email).toLowerCase() }, defaults: { password_hash: await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12), display_name: profile.name ?? profile.email, role: 'analyst' } });
    response.json({ access_token: signAccessToken(user), token_type: 'Bearer', expires_in: 28800, user: { email: user.email, display_name: user.display_name, role: user.role } });
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
  app.post('/api/v1/auth/change-password', asyncHandler(async (request, response) => {
    const currentPassword = String(request.body.current_password ?? '');
    const newPassword = String(request.body.new_password ?? '');
    if (newPassword.length < 8) return response.status(400).json({ detail: 'La nueva contraseña debe tener al menos 8 caracteres' });
    const user = await User.findByPk(request.user.sub);
    if (!user || !await bcrypt.compare(currentPassword, user.password_hash)) return response.status(401).json({ detail: 'La contraseña actual es incorrecta' });
    await user.update({ password_hash: await bcrypt.hash(newPassword, 12) });
    await recordAudit(request, 'PASSWORD_CHANGED', `user:${user.id}`);
    response.json({ changed: true });
  }));
  app.post('/api/v1/auth/mfa/setup', asyncHandler(async (request, response) => {
    const user = await User.findByPk(request.user.sub);
    const secret = createTotpSecret();
    const [setting] = await MfaSetting.findOrCreate({ where: { user_id: user.id }, defaults: { secret, enabled: false, recovery_codes: [] } });
    if (setting.secret !== secret) await setting.update({ secret, enabled: false });
    response.json({ secret, otpauth_uri: totpUri(secret, user.email) });
  }));
  app.post('/api/v1/auth/mfa/enable', asyncHandler(async (request, response) => {
    const setting = await MfaSetting.findOne({ where: { user_id: request.user.sub } });
    if (!setting || !verifyTotp(setting.secret, request.body.code)) return response.status(400).json({ detail: 'Código MFA incorrecto' });
    await setting.update({ enabled: true }); await recordAudit(request, 'MFA_ENABLED', `user:${request.user.sub}`); response.json({ enabled: true });
  }));
  app.post('/api/v1/auth/mfa/disable', asyncHandler(async (request, response) => {
    const setting = await MfaSetting.findOne({ where: { user_id: request.user.sub } });
    if (setting) await setting.update({ enabled: false }); await recordAudit(request, 'MFA_DISABLED', `user:${request.user.sub}`); response.json({ enabled: false });
  }));

  app.get('/api/v1/assets', asyncHandler(async (_request, response) => {
    response.json(await Asset.findAll({ order: [['createdAt', 'DESC']] }));
  }));
  app.post('/api/v1/assets', asyncHandler(async (request, response) => {
    const asset = await Asset.create(assetPayload(request.body)); await recordAudit(request, 'ASSET_CREATED', `asset:${asset.id}`); response.status(201).json(asset);
  }));
  app.get('/api/v1/assets/:id', asyncHandler(async (request, response) => {
    const asset = await Asset.findByPk(request.params.id);
    if (!asset) throw notFound('Activo no encontrado');
    response.json(asset);
  }));
  app.put('/api/v1/assets/:id', asyncHandler(async (request, response) => {
    const asset = await Asset.findByPk(request.params.id);
    if (!asset) throw notFound('Activo no encontrado');
    await asset.update(assetPayload(request.body)); await recordAudit(request, 'ASSET_UPDATED', `asset:${asset.id}`); response.json(asset);
  }));
  app.delete('/api/v1/assets/:id', asyncHandler(async (request, response) => {
    const asset = await Asset.findByPk(request.params.id);
    if (!asset) throw notFound('Activo no encontrado');
    await asset.destroy(); await recordAudit(request, 'ASSET_DELETED', `asset:${request.params.id}`);
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
    await recordAudit(request, 'RISK_CREATED', `risk:${created.id}`, { score: created.score, level: created.level });
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
    await recordAudit(request, 'RISK_UPDATED', `risk:${risk.id}`, { score: risk.score, level: risk.level });
    const updated = await RiskAssessment.findByPk(risk.id, { include: [{ model: Asset, as: 'asset', attributes: ['name'] }] });
    response.json(riskJson(updated));
  }));
  app.delete('/api/v1/risks/:id', asyncHandler(async (request, response) => {
    const risk = await RiskAssessment.findByPk(request.params.id);
    if (!risk) throw notFound('Riesgo no encontrado');
    await risk.destroy(); await recordAudit(request, 'RISK_DELETED', `risk:${request.params.id}`);
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
    const report = await buildExecutiveReport(await collectExecutiveReportData(models));
    response.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="informe-ejecutivo-riesgos.pdf"', 'Content-Length': report.length });
    response.send(report);
  }));

  registerPlatformRoutes(app, models);

  app.use((_request, response) => response.status(404).json({ detail: 'Ruta no encontrada' }));
  app.use((error, _request, response, _next) => {
    const validationError = error instanceof ValidationError;
    const status = error.status ?? (validationError ? 400 : 500);
    if (status >= 500) console.error(error);
    response.status(status).json({ detail: validationError ? error.errors.map((item) => item.message).join(', ') : error.message });
  });
  return app;
}
