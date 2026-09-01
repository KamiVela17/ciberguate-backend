import bcrypt from 'bcryptjs';
import { newDb } from 'pg-mem';
import { Sequelize } from 'sequelize';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

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
});
