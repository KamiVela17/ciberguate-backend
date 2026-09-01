# CiberGuate Backend

API Node.js 22 con Express, Sequelize, PostgreSQL, Swagger y PDFKit. El pipeline
ejecuta pruebas y auditoría; en `main` publica una imagen ECR con etiqueta igual
al SHA completo del commit y actualiza el overlay `dev` del repositorio GitOps.

```powershell
npm install
Copy-Item .env.example .env
npm run dev
```

Swagger queda disponible en `/docs` y la comprobación de salud en `/health`.
Variables del repositorio GitHub: `AWS_REGION`, `ECR_REPOSITORY` y
`GITOPS_REPOSITORY`. Secretos: `AWS_ROLE_ARN` y `GITOPS_DEPLOY_KEY`.
