import bcrypt from 'bcryptjs';

export async function seedDatabase({ User, Asset, RiskAssessment, ComplianceControl, Alert, SecurityEvent, Incident, EvidenceDocument }) {
  const adminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminEmail && adminPassword && !await User.findOne({ where: { email: adminEmail } })) {
    await User.create({ email: adminEmail, password_hash: await bcrypt.hash(adminPassword, 12), display_name: 'Administrador CiberGuate', role: 'admin' });
  }

  if (await Asset.count() === 0) {
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

  if (await ComplianceControl.count() === 0) await ComplianceControl.bulkCreate([
    { framework: 'ISO 27001', code: 'A.5.1', title: 'Políticas de seguridad de la información', description: 'Definir, aprobar y revisar políticas institucionales.', status: 'Parcial', score: 50 },
    { framework: 'ISO 27001', code: 'A.5.23', title: 'Seguridad para servicios en nube', description: 'Gestionar adquisición, uso y salida de servicios cloud.', status: 'Parcial', score: 50 },
    { framework: 'ISO 27001', code: 'A.8.8', title: 'Gestión de vulnerabilidades técnicas', description: 'Identificar y tratar vulnerabilidades oportunamente.', status: 'Pendiente', score: 0 },
    { framework: 'NIST CSF 2.0', code: 'GV.RM-01', title: 'Objetivos de gestión de riesgo', status: 'Parcial', score: 50 },
    { framework: 'NIST CSF 2.0', code: 'ID.AM-01', title: 'Inventario de activos físicos', status: 'Implementado', score: 100 },
    { framework: 'NIST CSF 2.0', code: 'DE.CM-01', title: 'Monitoreo continuo de redes y servicios', status: 'Parcial', score: 50 },
    { framework: 'CIS Controls v8', code: 'CIS-1', title: 'Inventario y control de activos empresariales', status: 'Implementado', score: 100 },
    { framework: 'CIS Controls v8', code: 'CIS-7', title: 'Gestión continua de vulnerabilidades', status: 'Parcial', score: 50 },
    { framework: 'OWASP Top 10', code: 'A01:2021', title: 'Control de acceso roto', status: 'Parcial', score: 50 },
    { framework: 'OWASP Top 10', code: 'A05:2021', title: 'Configuración de seguridad incorrecta', status: 'Pendiente', score: 0 },
    { framework: 'MITRE ATT&CK', code: 'TA0001', title: 'Acceso inicial', status: 'Parcial', score: 50 },
    { framework: 'MITRE ATT&CK', code: 'TA0040', title: 'Impacto', status: 'Pendiente', score: 0 },
  ]);

  const firstAsset = await Asset.findOne();
  if (await SecurityEvent.count() === 0) await SecurityEvent.bulkCreate([
    { source: 'AWS CloudTrail', event_type: 'Inicio de sesión administrativo', severity: 'Informativa', description: 'Autenticación administrativa registrada.', asset_id: firstAsset?.id },
    { source: 'WAF', event_type: 'Intentos de inyección bloqueados', severity: 'Alta', description: 'Múltiples solicitudes con patrones anómalos fueron bloqueadas.', asset_id: firstAsset?.id },
  ]);
  if (await Alert.count() === 0) await Alert.create({ title: 'Patrones anómalos en aplicación pública', severity: 'Alta', source: 'SIEM: WAF', details: 'Se recomienda revisar origen, reglas WAF y registros de aplicación.', asset_id: firstAsset?.id });
  if (await Incident.count() === 0) await Incident.create({ title: 'Investigación de actividad web anómala', severity: 'Alta', status: 'Abierto', description: 'Incidente generado para validar los eventos detectados por WAF.', assigned_to: 'Equipo SOC', playbook: 'Contención de aplicación web', asset_id: firstAsset?.id });
  if (await EvidenceDocument.count() === 0) await EvidenceDocument.create({ name: 'Política de seguridad institucional', category: 'Política', mime_type: 'text/plain', content: 'Documento demostrativo sujeto a aprobación y control de versiones.', size_bytes: 67, uploaded_by: adminEmail ?? 'sistema' });
}
