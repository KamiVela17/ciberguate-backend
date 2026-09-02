const requiredHeaders = [
  ['content-security-policy', 'Content-Security-Policy', 'Alta'],
  ['strict-transport-security', 'Strict-Transport-Security', 'Alta'],
  ['x-content-type-options', 'X-Content-Type-Options', 'Media'],
  ['x-frame-options', 'X-Frame-Options', 'Media'],
  ['referrer-policy', 'Referrer-Policy', 'Baja'],
  ['permissions-policy', 'Permissions-Policy', 'Baja'],
];

export function validateTarget(value) {
  const raw = String(value ?? '').trim();
  if (!raw) throw Object.assign(new Error('Debe ingresar una URL para ejecutar el diagnóstico'), { status: 400 });
  const normalized = /^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let target;
  try { target = new URL(normalized); } catch { throw Object.assign(new Error('La URL ingresada no es válida'), { status: 400 }); }
  if (!['http:', 'https:'].includes(target.protocol)) throw Object.assign(new Error('El objetivo debe utilizar HTTP o HTTPS'), { status: 400 });
  if (target.username || target.password) throw Object.assign(new Error('No se permiten credenciales en la URL'), { status: 400 });
  const hostname = target.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname === '::1' || hostname.startsWith('127.') || hostname.startsWith('169.254.') || hostname.startsWith('10.') || /^192\.168\./.test(hostname) || /^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) {
    throw Object.assign(new Error('No se permite diagnosticar direcciones locales o redes privadas'), { status: 400 });
  }
  return target;
}

export async function scanWebTarget(value) {
  const target = validateTarget(value);
  const started = Date.now();
  const findings = [];
  let response;
  try {
    response = await fetch(target, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(10000), headers: { 'User-Agent': 'CiberGuate-Security-Diagnostic/1.0' } });
  } catch (error) {
    findings.push({ code: 'AVAILABILITY', title: 'Servicio no disponible', severity: 'Crítica', evidence: error.message, recommendation: 'Verifique DNS, conectividad, certificados y disponibilidad del servicio.' });
    return { status: 'Fallido', latency_ms: Date.now() - started, risk_score: 100, findings, summary: 'El objetivo no respondió al diagnóstico automático.' };
  }

  if (target.protocol !== 'https:') findings.push({ code: 'TLS_REQUIRED', title: 'Transporte sin HTTPS', severity: 'Crítica', evidence: target.href, recommendation: 'Habilite TLS y redirija todo el tráfico HTTP hacia HTTPS.' });
  if (response.status >= 400) findings.push({ code: 'HTTP_STATUS', title: `Respuesta HTTP ${response.status}`, severity: response.status >= 500 ? 'Alta' : 'Media', evidence: response.statusText, recommendation: 'Revise la disponibilidad y configuración del endpoint.' });
  for (const [header, title, severity] of requiredHeaders) {
    if (!response.headers.get(header)) findings.push({ code: `HEADER_${header.toUpperCase()}`, title: `Falta ${title}`, severity, evidence: 'Encabezado ausente', recommendation: `Configure el encabezado ${title} con una política apropiada.` });
  }
  const server = response.headers.get('server');
  if (server && /\d/.test(server)) findings.push({ code: 'SERVER_DISCLOSURE', title: 'Divulgación de versión del servidor', severity: 'Baja', evidence: server, recommendation: 'Oculte versiones específicas en encabezados HTTP.' });
  const weights = { Crítica: 25, Alta: 15, Media: 8, Baja: 3 };
  const riskScore = Math.min(100, findings.reduce((sum, item) => sum + (weights[item.severity] ?? 1), 0));
  return { status: 'Completado', http_status: response.status, latency_ms: Date.now() - started, risk_score: riskScore, findings, summary: findings.length ? `Se identificaron ${findings.length} hallazgos de exposición web.` : 'No se identificaron hallazgos en las comprobaciones no intrusivas.' };
}
