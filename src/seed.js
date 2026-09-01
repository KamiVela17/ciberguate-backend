import bcrypt from 'bcryptjs';

export async function seedDatabase({ User, Asset, RiskAssessment }) {
  const adminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminEmail && adminPassword && !await User.findOne({ where: { email: adminEmail } })) {
    await User.create({
      email: adminEmail,
      password_hash: await bcrypt.hash(adminPassword, 12),
      display_name: 'Administrador CiberGuate',
      role: 'admin',
    });
  }
  if (await Asset.count() > 0) return;
  const assets = await Asset.bulkCreate([
    { name: 'Portal de servicios ciudadanos', asset_type: 'Aplicación', owner: 'Tecnología', location: 'AWS Guatemala', criticality: 5, status: 'Activo' },
    { name: 'Base de datos de contribuyentes', asset_type: 'Base de datos', owner: 'Finanzas', location: 'Centro de datos', criticality: 5, status: 'Activo' },
    { name: 'Servidor de correo institucional', asset_type: 'Servidor', owner: 'Infraestructura', location: 'Nube privada', criticality: 4, status: 'Activo' },
    { name: 'Red de sedes municipales', asset_type: 'Red', owner: 'Operaciones', location: 'Nacional', criticality: 3, status: 'En revisión' },
  ]);
  await RiskAssessment.bulkCreate([
    { title: 'Acceso no autorizado a datos', threat: 'Credenciales comprometidas', likelihood: 5, impact: 5, score: 25, level: 'Crítico', status: 'Abierto', nist_function: 'PROTECT', asset_id: assets[1].id },
    { title: 'Interrupción del portal público', threat: 'Ataque DDoS', likelihood: 4, impact: 4, score: 16, level: 'Alto', status: 'En tratamiento', nist_function: 'RESPOND', asset_id: assets[0].id },
    { title: 'Propagación de ransomware', threat: 'Malware', likelihood: 3, impact: 5, score: 15, level: 'Alto', status: 'Abierto', nist_function: 'RECOVER', asset_id: assets[2].id },
    { title: 'Configuración insegura de red', threat: 'Error de configuración', likelihood: 3, impact: 3, score: 9, level: 'Medio', status: 'Mitigado', nist_function: 'IDENTIFY', asset_id: assets[3].id },
  ]);
}
