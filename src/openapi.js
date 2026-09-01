const assetSchema = {
  type: 'object',
  required: ['name', 'asset_type', 'owner', 'location'],
  properties: {
    name: { type: 'string', example: 'ERP institucional' },
    asset_type: { type: 'string', example: 'Aplicación' },
    owner: { type: 'string', example: 'Finanzas' },
    location: { type: 'string', example: 'Nube privada' },
    criticality: { type: 'integer', minimum: 1, maximum: 5, default: 3 },
    status: { type: 'string', default: 'Activo' },
    description: { type: 'string', nullable: true },
  },
};
const riskSchema = {
  type: 'object',
  required: ['title', 'threat', 'likelihood', 'impact', 'asset_id'],
  properties: {
    title: { type: 'string' }, threat: { type: 'string' },
    likelihood: { type: 'integer', minimum: 1, maximum: 5 },
    impact: { type: 'integer', minimum: 1, maximum: 5 },
    asset_id: { type: 'integer' }, status: { type: 'string', default: 'Abierto' },
    nist_function: { type: 'string', enum: ['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER'] },
    notes: { type: 'string', nullable: true },
  },
};

export const openapi = {
  openapi: '3.0.3',
  info: { title: 'CiberGuate IA API', version: '1.0.0', description: 'Inventario, evaluación NIST y priorización de riesgos.' },
  servers: [{ url: '/' }],
  paths: {
    '/health': { get: { tags: ['Sistema'], responses: { 200: { description: 'Servicio saludable' } } } },
    '/api/v1/assets': {
      get: { tags: ['Activos'], responses: { 200: { description: 'Inventario de activos' } } },
      post: { tags: ['Activos'], requestBody: { required: true, content: { 'application/json': { schema: assetSchema } } }, responses: { 201: { description: 'Activo creado' } } },
    },
    '/api/v1/assets/{id}': {
      get: { tags: ['Activos'], parameters: [{ in: 'path', name: 'id', required: true, schema: { type: 'integer' } }], responses: { 200: { description: 'Activo' }, 404: { description: 'No encontrado' } } },
      put: { tags: ['Activos'], parameters: [{ in: 'path', name: 'id', required: true, schema: { type: 'integer' } }], requestBody: { required: true, content: { 'application/json': { schema: assetSchema } } }, responses: { 200: { description: 'Activo actualizado' } } },
      delete: { tags: ['Activos'], parameters: [{ in: 'path', name: 'id', required: true, schema: { type: 'integer' } }], responses: { 204: { description: 'Activo eliminado' } } },
    },
    '/api/v1/risks': {
      get: { tags: ['Riesgos'], responses: { 200: { description: 'Evaluaciones de riesgo' } } },
      post: { tags: ['Riesgos'], requestBody: { required: true, content: { 'application/json': { schema: riskSchema } } }, responses: { 201: { description: 'Riesgo evaluado' } } },
    },
    '/api/v1/dashboard': { get: { tags: ['Analítica'], responses: { 200: { description: 'Resumen ejecutivo' } } } },
    '/api/v1/recommendations': { get: { tags: ['Analítica'], responses: { 200: { description: 'Recomendaciones priorizadas' } } } },
    '/api/v1/reports/executive.pdf': { get: { tags: ['Reportes'], responses: { 200: { description: 'Informe PDF', content: { 'application/pdf': {} } } } } },
  },
};
