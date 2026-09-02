import bcrypt from 'bcryptjs';
import { newDb } from 'pg-mem';
import { Sequelize } from 'sequelize';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { createApp } from '../src/app.js';
import { defineModels } from '../src/models/index.js';

const memory = newDb();
memory.public.registerFunction({ name: 'current_database', implementation: () => 'ciberguate_test' });
memory.public.registerFunction({ name: 'version', implementation: () => 'PostgreSQL 16.0' });
const pg = memory.adapters.createPg();
const database = new Sequelize('postgres://test:test@localhost:5432/test', { dialect: 'postgres', dialectModule: pg, logging: false });
const models = defineModels(database);
const app = createApp({ models, database });
let authorization;

beforeAll(async () => {
  process.env.JWT_SECRET = 'test-signing-key-with-at-least-32-characters';
  await database.sync({ force: true });
  await models.User.create({ email: 'admin@example.test', password_hash: await bcrypt.hash('correct-horse-battery-staple', 4), display_name: 'Admin Test', role: 'admin' });
  const login = await request(app).post('/api/v1/auth/login').send({ email: 'admin@example.test', password: 'correct-horse-battery-staple' }).expect(200);
  authorization = `Bearer ${login.body.access_token}`;
});
afterAll(async () => database.close());

describe('API del MVP', () => {
  it('ejecuta el flujo completo de activo, riesgo, dashboard y PDF', async () => {
    const asset = await request(app).post('/api/v1/assets').set('Authorization', authorization).send({ name: 'ERP institucional', asset_type: 'Aplicación', owner: 'Finanzas', location: 'Nube privada', criticality: 5, status: 'Activo' }).expect(201);
    const risk = await request(app).post('/api/v1/risks').set('Authorization', authorization).send({ title: 'Cifrado por ransomware', threat: 'Ransomware', likelihood: 5, impact: 5, asset_id: asset.body.id, nist_function: 'RECOVER', status: 'Abierto' }).expect(201);
    expect(risk.body).toMatchObject({ score: 25, level: 'Crítico', asset_name: 'ERP institucional' });
    const dashboard = await request(app).get('/api/v1/dashboard').set('Authorization', authorization).expect(200);
    expect(dashboard.body).toMatchObject({ total_assets: 1, critical_assets: 1, critical_risks: 1 });
    const recommendations = await request(app).get('/api/v1/recommendations').set('Authorization', authorization).expect(200);
    expect(recommendations.body[0].framework).toBe('NIST RC.RP / CIS 11');
    const report = await request(app).get('/api/v1/reports/executive.pdf').set('Authorization', authorization).expect('Content-Type', /pdf/).expect(200);
    expect(report.body.subarray(0, 4).toString()).toBe('%PDF');
  });

  it('rechaza un riesgo asociado a un activo inexistente', async () => {
    await request(app).post('/api/v1/risks').set('Authorization', authorization).send({ title: 'Riesgo inválido', threat: 'Amenaza', likelihood: 3, impact: 4, asset_id: 999, nist_function: 'PROTECT' }).expect(404);
  });

  it('protege rutas y rechaza credenciales incorrectas', async () => {
    await request(app).get('/api/v1/assets').expect(401);
    await request(app).post('/api/v1/auth/login').send({ email: 'admin@example.test', password: 'incorrecta' }).expect(401);
  });

  it('publica OpenAPI y valida objetivos de diagnóstico con mensajes seguros', async () => {
    await request(app).get('/api/openapi.json').expect(200).expect((response) => expect(response.body.openapi).toBe('3.0.3'));
    await request(app).get('/docs/').expect('Content-Type', /html/).expect(200);
    await request(app).get('/api/docs/').expect('Content-Type', /html/).expect(200);
    await request(app).post('/api/v1/scans').set('Authorization', authorization).send({ target: 'no es una url' }).expect(400);
    await request(app).post('/api/v1/scans').set('Authorization', authorization).send({ target: 'http://127.0.0.1' }).expect(400);
  });

  it('opera cumplimiento, documentos, SIEM, alertas, incidentes e inteligencia analítica', async () => {
    const control = await models.ComplianceControl.create({ framework: 'ISO 27001', code: 'A.8.8', title: 'Gestión de vulnerabilidades', status: 'Pendiente', score: 0 });
    await request(app).put(`/api/v1/compliance/${control.id}`).set('Authorization', authorization).send({ status: 'Implementado', evidence: 'Acta de revisión aprobada' }).expect(200);
    const compliance = await request(app).get('/api/v1/compliance').set('Authorization', authorization).expect(200);
    expect(compliance.body).toMatchObject({ overall_score: 100 });

    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 200, headers: { 'content-security-policy': "default-src 'self'", 'strict-transport-security': 'max-age=31536000', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=()' } })));
    const scan = await request(app).post('/api/v1/scans').set('Authorization', authorization).send({ target: 'example.test' }).expect(201);
    expect(scan.body.target).toBe('https://example.test/');
    vi.unstubAllGlobals();
    const automatic = await request(app).post('/api/v1/compliance/automatic-assessment').set('Authorization', authorization).expect(200);
    expect(automatic.body.evaluated_controls).toBe(1);

    await request(app).post('/api/v1/documents').set('Authorization', authorization).send({ name: 'Política institucional', category: 'Política', content: 'Contenido aprobado por el comité.' }).expect(201);
    const documents = await request(app).get('/api/v1/documents').set('Authorization', authorization).expect(200);
    expect(documents.body).toHaveLength(1);
    expect(documents.body[0]).not.toHaveProperty('content');

    await request(app).post('/api/v1/events').set('Authorization', authorization).send({ source: 'WAF', event_type: 'Ataque bloqueado', severity: 'Alta', description: 'Patrón de inyección detectado' }).expect(201);
    const alerts = await request(app).get('/api/v1/alerts').set('Authorization', authorization).expect(200);
    expect(alerts.body[0]).toMatchObject({ severity: 'Alta', source: 'SIEM: WAF' });

    const incident = await request(app).post('/api/v1/incidents').set('Authorization', authorization).send({ title: 'Actividad web anómala', severity: 'Alta', description: 'Investigar solicitudes bloqueadas', assigned_to: 'SOC' }).expect(201);
    await request(app).post(`/api/v1/incidents/${incident.body.id}/respond`).set('Authorization', authorization).send({ action_type: 'Bloqueo preventivo' }).expect(201);
    const incidents = await request(app).get('/api/v1/incidents').set('Authorization', authorization).expect(200);
    expect(incidents.body[0]).toMatchObject({ status: 'Contenido' });

    const analysis = await request(app).get('/api/v1/ai/analysis').set('Authorization', authorization).expect(200);
    expect(analysis.body).toEqual(expect.objectContaining({ mode: 'motor-analitico-local', attack_probability: expect.any(Number), recommendations: expect.any(Array) }));
  });
});
