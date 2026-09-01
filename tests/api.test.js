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

beforeAll(async () => database.sync({ force: true }));
afterAll(async () => database.close());

describe('API del MVP', () => {
  it('ejecuta el flujo completo de activo, riesgo, dashboard y PDF', async () => {
    const asset = await request(app).post('/api/v1/assets').send({ name: 'ERP institucional', asset_type: 'Aplicación', owner: 'Finanzas', location: 'Nube privada', criticality: 5, status: 'Activo' }).expect(201);
    const risk = await request(app).post('/api/v1/risks').send({ title: 'Cifrado por ransomware', threat: 'Ransomware', likelihood: 5, impact: 5, asset_id: asset.body.id, nist_function: 'RECOVER', status: 'Abierto' }).expect(201);
    expect(risk.body).toMatchObject({ score: 25, level: 'Crítico', asset_name: 'ERP institucional' });

    const dashboard = await request(app).get('/api/v1/dashboard').expect(200);
    expect(dashboard.body).toMatchObject({ total_assets: 1, critical_assets: 1, critical_risks: 1 });

    const recommendations = await request(app).get('/api/v1/recommendations').expect(200);
    expect(recommendations.body[0].framework).toBe('NIST RC.RP / CIS 11');

    const report = await request(app).get('/api/v1/reports/executive.pdf').expect('Content-Type', /pdf/).expect(200);
    expect(report.body.subarray(0, 4).toString()).toBe('%PDF');
  });

  it('rechaza un riesgo asociado a un activo inexistente', async () => {
    await request(app).post('/api/v1/risks').send({ title: 'Riesgo inválido', threat: 'Amenaza', likelihood: 3, impact: 4, asset_id: 999, nist_function: 'PROTECT' }).expect(404);
  });
});
