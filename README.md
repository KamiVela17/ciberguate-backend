# CiberGuate IA — Backend

API Node.js 22 con Express, Sequelize y PostgreSQL para activos, riesgos, diagnóstico web, monitoreo, alertas, cumplimiento, documentos, SOC/SIEM, incidentes, IA, auditoría y reportes PDF.

## Inicio rápido

```bash
npm ci
cp .env.example .env
npm run dev
```

- Salud: `GET /health`
- Swagger UI: `/docs` o `/api/docs`
- OpenAPI JSON: `/api/openapi.json`
- API: `/api/v1`

Salvo login, MFA de login, configuración/callback OAuth2, documentación y salud, las rutas requieren `Authorization: Bearer <JWT>`.

## Documentación

El índice completo está en [docs/README.md](docs/README.md):

- [Arquitectura](docs/architecture.md)
- [API](docs/api.md)
- [Modelo de datos](docs/data-model.md)
- [Casos de uso](docs/use-cases.md)
- [Motor de diagnóstico](docs/diagnostic-engine.md)
- [IA y reportes](docs/ai-and-reporting.md)
- [Seguridad](docs/security.md)
- [Desarrollo y pruebas](docs/development-and-testing.md)

En `main`, CI ejecuta pruebas y auditoría, publica en Amazon ECR una imagen con el SHA completo del commit y actualiza el repositorio GitOps.
