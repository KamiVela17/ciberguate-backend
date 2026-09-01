import 'dotenv/config';

import { createApp } from './app.js';
import { sequelize } from './config/database.js';
import { defineModels } from './models/index.js';
import { seedDatabase } from './seed.js';

const port = Number(process.env.PORT ?? 8000);
const models = defineModels(sequelize);

async function connectWithRetry(attempts = 10) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      await sequelize.authenticate();
      await sequelize.sync();
      return;
    } catch (error) {
      if (attempt === attempts) throw error;
      console.warn(`PostgreSQL no disponible (intento ${attempt}/${attempts}); reintentando...`);
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }
}

await connectWithRetry();
if ((process.env.SEED_DATA ?? 'true').toLowerCase() === 'true') await seedDatabase(models);

const app = createApp({ models, database: sequelize });
const server = app.listen(port, '0.0.0.0', () => console.log(`CiberGuate IA API escuchando en el puerto ${port}`));

async function shutdown() {
  server.close(async () => {
    await sequelize.close();
    process.exit(0);
  });
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
