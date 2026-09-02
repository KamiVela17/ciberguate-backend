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

const listEndpoint = (tag, description) => ({ get: { tags: [tag], security: [{ bearerAuth: [] }], responses: { 200: { description } } } });

export const openapi = {
  openapi: '3.0.3',
  info: { title: 'CiberGuate IA API', version: '2.0.0', description: 'API operativa para diagnóstico, inventario, riesgos, monitoreo, cumplimiento, SOC, incidentes, IA y reportes.' },
  servers: [{ url: '/' }],
  components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } } },
  security: [{ bearerAuth: [] }],
  paths: {
    '/health': { get: { tags: ['Sistema'], security: [], responses: { 200: { description: 'Servicio saludable' } } } },
    '/api/v1/auth/login': {
      post: {
        tags: ['Autenticación'], security: [],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['email', 'password'], properties: { email: { type: 'string', format: 'email' }, password: { type: 'string', format: 'password' } } } } } },
        responses: { 200: { description: 'Sesión JWT o desafío MFA' }, 401: { description: 'Credenciales incorrectas' } },
      },
    },
    '/api/v1/auth/change-password': { post: { tags: ['Autenticación'], summary: 'Cambiar contraseña del usuario autenticado', responses: { 200: { description: 'Contraseña actualizada' }, 400: { description: 'Contraseña débil' }, 401: { description: 'Contraseña actual incorrecta' } } } },
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
    '/api/v1/security/overview': listEndpoint('Analítica', 'Postura operativa consolidada'),
    '/api/v1/scans': {
      ...listEndpoint('Diagnóstico', 'Diagnósticos automáticos y hallazgos'),
      post: {
        tags: ['Diagnóstico'], summary: 'Ejecutar diagnóstico web',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['target'], properties: { target: { type: 'string', example: 'https://example.com' }, asset_id: { type: 'integer', nullable: true } } } } } },
        responses: { 201: { description: 'Diagnóstico completado con hallazgos' }, 400: { description: 'Objetivo inválido o privado' } },
      },
    },
    '/api/v1/monitors': {
      ...listEndpoint('Monitoreo', 'Objetivos y disponibilidad continua'),
      post: {
        tags: ['Monitoreo'], summary: 'Crear monitor y ejecutar primera verificación',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['name', 'target'], properties: { name: { type: 'string' }, target: { type: 'string' }, interval_minutes: { type: 'integer', default: 5 } } } } } },
        responses: { 201: { description: 'Monitor creado' } },
      },
    },
    '/api/v1/alerts': listEndpoint('SOC', 'Alertas inteligentes correlacionadas'),
    '/api/v1/compliance': listEndpoint('Cumplimiento', 'Evaluación multiestándar y evidencia'),
    '/api/v1/compliance/automatic-assessment': { post: { tags: ['Cumplimiento'], summary: 'Evaluar automáticamente todos los controles', responses: { 200: { description: 'Evaluación y evidencia actualizadas' } } } },
    '/api/v1/documents': listEndpoint('Documentos', 'Repositorio de evidencias'),
    '/api/v1/events': {
      ...listEndpoint('SIEM', 'Eventos de seguridad consolidados'),
      post: { tags: ['SIEM'], summary: 'Ingerir evento de seguridad', responses: { 201: { description: 'Evento almacenado y correlacionado' } } },
    },
    '/api/v1/incidents': {
      ...listEndpoint('Incidentes', 'Gestión y respuesta de incidentes'),
      post: { tags: ['Incidentes'], summary: 'Crear incidente', responses: { 201: { description: 'Incidente creado' } } },
    },
    '/api/v1/ai/analysis': listEndpoint('Inteligencia artificial', 'Predicción y recomendaciones inteligentes'),
    '/api/v1/reports/monthly': listEndpoint('Reportes', 'Archivo mensual automático'),
    '/api/v1/audit-logs': listEndpoint('Zero Trust', 'Bitácora de acciones sensibles'),
  },
};
