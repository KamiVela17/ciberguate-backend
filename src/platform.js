import { Op } from 'sequelize';

import { analyzeSecurityPosture } from './services/ai.js';
import { scanWebTarget, validateTarget } from './services/scanner.js';
import { buildExecutiveReport, collectExecutiveReportData } from './services/report.js';

const asyncHandler = (handler) => (request, response, next) => Promise.resolve(handler(request, response, next)).catch(next);
const notFound = (message) => Object.assign(new Error(message), { status: 404 });

async function audit(models, request, action, resource, metadata = {}) {
  await models.AuditLog.create({ actor: request.user.email, action, resource, ip_address: request.ip, metadata });
}

async function executeScan(models, scan) {
  await scan.update({ status: 'Ejecutando', started_at: new Date() });
  const result = await scanWebTarget(scan.target);
  await scan.update({ status: result.status, risk_score: result.risk_score, findings_count: result.findings.length, findings: result.findings, summary: result.summary, completed_at: new Date() });
  for (const finding of result.findings.filter((item) => ['Crítica', 'Alta'].includes(item.severity))) {
    const existing = await models.Alert.findOne({ where: { source: 'Diagnóstico', title: finding.title, asset_id: scan.asset_id ?? null, status: { [Op.notIn]: ['Cerrada'] } } });
    if (!existing) await models.Alert.create({ title: finding.title, severity: finding.severity, source: 'Diagnóstico', details: `${finding.evidence}. ${finding.recommendation}`, asset_id: scan.asset_id ?? null });
  }
  return scan.reload();
}

export async function executeMonitor(models, monitor) {
  const started = Date.now();
  let success = false;
  let details = '';
  try {
    validateTarget(monitor.target);
    const response = await fetch(monitor.target, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'CiberGuate-Monitor/1.0' } });
    success = response.status < 500;
    details = `HTTP ${response.status}`;
  } catch (error) {
    details = error.message;
  }
  const total = monitor.checks_total + 1;
  const successful = monitor.checks_successful + (success ? 1 : 0);
  await monitor.update({
    status: success ? 'Operativo' : 'Caído', checks_total: total, checks_successful: successful,
    availability_percentage: Number(((successful / total) * 100).toFixed(2)), latency_ms: Date.now() - started,
    last_checked_at: new Date(), next_check_at: new Date(Date.now() + monitor.interval_minutes * 60_000),
  });
  if (!success) {
    const existing = await models.Alert.findOne({ where: { source: 'Monitoreo', title: `Servicio no disponible: ${monitor.name}`, status: { [Op.notIn]: ['Cerrada'] } } });
    if (!existing) await models.Alert.create({ title: `Servicio no disponible: ${monitor.name}`, severity: 'Crítica', source: 'Monitoreo', details, asset_id: monitor.asset_id ?? null });
  }
  return monitor.reload();
}

export function registerPlatformRoutes(app, models) {
  const { Asset, RiskAssessment, ComplianceControl, VulnerabilityScan, Monitor, Alert, EvidenceDocument, SecurityEvent, Incident, AutomatedAction, AuditLog, ReportSnapshot } = models;

  app.get('/api/v1/security/overview', asyncHandler(async (_request, response) => {
    const [scans, monitors, alerts, controls, events, incidents, documents] = await Promise.all([
      VulnerabilityScan.count(), Monitor.findAll(), Alert.findAll(), ComplianceControl.findAll(), SecurityEvent.count(), Incident.findAll(), EvidenceDocument.count(),
    ]);
    const compliance = controls.length ? Math.round(controls.reduce((sum, item) => sum + item.score, 0) / controls.length) : 0;
    response.json({ scans, monitors: monitors.length, services_down: monitors.filter((item) => item.status === 'Caído').length, open_alerts: alerts.filter((item) => item.status !== 'Cerrada').length, critical_alerts: alerts.filter((item) => item.severity === 'Crítica' && item.status !== 'Cerrada').length, compliance, events, open_incidents: incidents.filter((item) => item.status !== 'Cerrado').length, documents });
  }));

  app.get('/api/v1/scans', asyncHandler(async (_request, response) => response.json(await VulnerabilityScan.findAll({ include: [{ model: Asset, as: 'asset', attributes: ['name'] }], order: [['createdAt', 'DESC']] }))));
  app.post('/api/v1/scans', asyncHandler(async (request, response) => {
    const target = validateTarget(request.body.target);
    const scan = await VulnerabilityScan.create({ target: target.href, asset_id: request.body.asset_id || null });
    const result = await executeScan(models, scan);
    await audit(models, request, 'SCAN_EXECUTED', `scan:${scan.id}`, { target: scan.target });
    response.status(201).json(result);
  }));

  app.get('/api/v1/monitors', asyncHandler(async (_request, response) => response.json(await Monitor.findAll({ include: [{ model: Asset, as: 'asset', attributes: ['name'] }], order: [['createdAt', 'DESC']] }))));
  app.post('/api/v1/monitors', asyncHandler(async (request, response) => {
    const target = validateTarget(request.body.target);
    const monitor = await Monitor.create({ name: request.body.name, target: target.href, interval_minutes: Number(request.body.interval_minutes ?? 5), asset_id: request.body.asset_id || null, next_check_at: new Date() });
    await audit(models, request, 'MONITOR_CREATED', `monitor:${monitor.id}`);
    response.status(201).json(await executeMonitor(models, monitor));
  }));
  app.post('/api/v1/monitors/:id/check', asyncHandler(async (request, response) => {
    const monitor = await Monitor.findByPk(request.params.id); if (!monitor) throw notFound('Monitor no encontrado');
    response.json(await executeMonitor(models, monitor));
  }));
  app.delete('/api/v1/monitors/:id', asyncHandler(async (request, response) => {
    const monitor = await Monitor.findByPk(request.params.id); if (!monitor) throw notFound('Monitor no encontrado');
    await monitor.destroy(); await audit(models, request, 'MONITOR_DELETED', `monitor:${request.params.id}`); response.status(204).end();
  }));

  app.get('/api/v1/alerts', asyncHandler(async (_request, response) => response.json(await Alert.findAll({ include: [{ model: Asset, as: 'asset', attributes: ['name'] }], order: [['detected_at', 'DESC']] }))));
  app.put('/api/v1/alerts/:id', asyncHandler(async (request, response) => {
    const alert = await Alert.findByPk(request.params.id); if (!alert) throw notFound('Alerta no encontrada');
    await alert.update({ status: request.body.status, acknowledged_at: request.body.status === 'Reconocida' ? new Date() : alert.acknowledged_at });
    await audit(models, request, 'ALERT_UPDATED', `alert:${alert.id}`, { status: alert.status }); response.json(alert);
  }));

  app.get('/api/v1/compliance', asyncHandler(async (_request, response) => {
    const controls = await ComplianceControl.findAll({ order: [['framework', 'ASC'], ['code', 'ASC']] });
    const frameworks = Object.entries(Object.groupBy(controls, (item) => item.framework)).map(([framework, items]) => ({ framework, score: Math.round(items.reduce((sum, item) => sum + item.score, 0) / items.length), implemented: items.filter((item) => item.status === 'Implementado').length, total: items.length }));
    response.json({ overall_score: controls.length ? Math.round(controls.reduce((sum, item) => sum + item.score, 0) / controls.length) : 0, frameworks, controls });
  }));
  app.put('/api/v1/compliance/:id', asyncHandler(async (request, response) => {
    const control = await ComplianceControl.findByPk(request.params.id); if (!control) throw notFound('Control no encontrado');
    const status = request.body.status ?? control.status;
    const defaultScore = { Pendiente: 0, Parcial: 50, Implementado: 100, 'No aplica': 100 }[status] ?? control.score;
    await control.update({ status, score: Number(request.body.score ?? defaultScore), evidence: request.body.evidence ?? control.evidence, owner: request.body.owner ?? control.owner, reviewed_at: new Date() });
    await audit(models, request, 'CONTROL_REVIEWED', `${control.framework}:${control.code}`, { status: control.status, score: control.score }); response.json(control);
  }));
  app.post('/api/v1/compliance/automatic-assessment', asyncHandler(async (request, response) => {
    const [assets, risks, scans, monitors, events, incidents, mfaEnabled] = await Promise.all([Asset.count(), RiskAssessment.count(), VulnerabilityScan.count(), Monitor.count(), SecurityEvent.count(), Incident.count(), models.MfaSetting.count({ where: { enabled: true } })]);
    const evidence = {
      'A.5.1': [75, 'Política y bitácora de auditoría disponibles'], 'A.5.23': [monitors + scans > 0 ? 75 : 25, `${monitors} monitores y ${scans} diagnósticos cloud`],
      'A.8.8': [scans > 0 ? 100 : 0, `${scans} diagnósticos de vulnerabilidades registrados`], 'GV.RM-01': [risks > 0 ? 100 : 0, `${risks} riesgos evaluados`],
      'ID.AM-01': [assets > 0 ? 100 : 0, `${assets} activos inventariados`], 'DE.CM-01': [monitors > 0 ? 100 : 0, `${monitors} servicios en monitoreo continuo`],
      'CIS-1': [assets > 0 ? 100 : 0, `${assets} activos controlados`], 'CIS-7': [scans > 0 ? 100 : 0, `${scans} evaluaciones técnicas`],
      'A01:2021': [mfaEnabled > 0 ? 100 : 70, `JWT activo; ${mfaEnabled} usuarios con MFA`], 'A05:2021': [scans > 0 ? 75 : 25, `${scans} comprobaciones de configuración web`],
      'TA0001': [events > 0 ? 75 : 25, `${events} eventos correlacionados por SIEM`], 'TA0040': [incidents > 0 ? 75 : 25, `${incidents} incidentes gestionados`],
    };
    const controls = await ComplianceControl.findAll();
    for (const control of controls) {
      const [score, automaticEvidence] = evidence[control.code] ?? [control.score, 'Sin regla automática para este control'];
      const status = score >= 90 ? 'Implementado' : score >= 40 ? 'Parcial' : 'Pendiente';
      await control.update({ score, status, evidence: `Evaluación automática: ${automaticEvidence}`, reviewed_at: new Date() });
    }
    await audit(models, request, 'AUTOMATIC_COMPLIANCE_ASSESSMENT', 'compliance', { controls: controls.length });
    response.json({ evaluated_controls: controls.length, evaluated_at: new Date() });
  }));

  app.get('/api/v1/documents', asyncHandler(async (_request, response) => response.json(await EvidenceDocument.findAll({ attributes: { exclude: ['content'] }, order: [['createdAt', 'DESC']] }))));
  app.post('/api/v1/documents', asyncHandler(async (request, response) => {
    const content = String(request.body.content ?? '');
    if (!content || Buffer.byteLength(content, 'utf8') > 750_000) throw Object.assign(new Error('El documento debe contener texto y no superar 750 KB'), { status: 400 });
    const document = await EvidenceDocument.create({ name: request.body.name, category: request.body.category, mime_type: request.body.mime_type ?? 'text/plain', content, size_bytes: Buffer.byteLength(content, 'utf8'), uploaded_by: request.user.email });
    await audit(models, request, 'DOCUMENT_UPLOADED', `document:${document.id}`); response.status(201).json({ ...document.toJSON(), content: undefined });
  }));
  app.get('/api/v1/documents/:id', asyncHandler(async (request, response) => { const document = await EvidenceDocument.findByPk(request.params.id); if (!document) throw notFound('Documento no encontrado'); response.json(document); }));
  app.delete('/api/v1/documents/:id', asyncHandler(async (request, response) => { const document = await EvidenceDocument.findByPk(request.params.id); if (!document) throw notFound('Documento no encontrado'); await document.destroy(); await audit(models, request, 'DOCUMENT_DELETED', `document:${request.params.id}`); response.status(204).end(); }));

  app.get('/api/v1/events', asyncHandler(async (_request, response) => response.json(await SecurityEvent.findAll({ include: [{ model: Asset, as: 'asset', attributes: ['name'] }], limit: 250, order: [['occurred_at', 'DESC']] }))));
  app.post('/api/v1/events', asyncHandler(async (request, response) => {
    const event = await SecurityEvent.create({ source: request.body.source, event_type: request.body.event_type, severity: request.body.severity, description: request.body.description, raw_data: request.body.raw_data ?? {}, asset_id: request.body.asset_id || null, occurred_at: request.body.occurred_at ?? new Date() });
    if (['Crítica', 'Alta'].includes(event.severity)) await Alert.create({ title: `${event.event_type} detectado`, severity: event.severity, source: `SIEM: ${event.source}`, details: event.description, asset_id: event.asset_id });
    await audit(models, request, 'SECURITY_EVENT_INGESTED', `event:${event.id}`, { severity: event.severity, source: event.source });
    response.status(201).json(event);
  }));

  app.get('/api/v1/incidents', asyncHandler(async (_request, response) => response.json(await Incident.findAll({ include: [{ model: Asset, as: 'asset', attributes: ['name'] }, { model: AutomatedAction, as: 'actions' }], order: [['createdAt', 'DESC']] }))));
  app.post('/api/v1/incidents', asyncHandler(async (request, response) => { const incident = await Incident.create({ title: request.body.title, severity: request.body.severity, description: request.body.description, assigned_to: request.body.assigned_to, playbook: request.body.playbook, asset_id: request.body.asset_id || null }); await audit(models, request, 'INCIDENT_CREATED', `incident:${incident.id}`); response.status(201).json(incident); }));
  app.put('/api/v1/incidents/:id', asyncHandler(async (request, response) => { const incident = await Incident.findByPk(request.params.id); if (!incident) throw notFound('Incidente no encontrado'); const status = request.body.status ?? incident.status; await incident.update({ status, assigned_to: request.body.assigned_to ?? incident.assigned_to, contained_at: status === 'Contenido' ? new Date() : incident.contained_at, closed_at: status === 'Cerrado' ? new Date() : incident.closed_at }); await audit(models, request, 'INCIDENT_UPDATED', `incident:${incident.id}`, { status }); response.json(incident); }));
  app.post('/api/v1/incidents/:id/respond', asyncHandler(async (request, response) => {
    const incident = await Incident.findByPk(request.params.id); if (!incident) throw notFound('Incidente no encontrado');
    const action = await AutomatedAction.create({ incident_id: incident.id, action_type: request.body.action_type ?? 'Activar playbook', details: request.body.details ?? `Playbook ejecutado: ${incident.playbook}`, status: 'Ejecutada' });
    await incident.update({ status: 'Contenido', contained_at: new Date() }); await audit(models, request, 'AUTOMATED_RESPONSE', `incident:${incident.id}`, { action: action.action_type }); response.status(201).json(action);
  }));

  app.get('/api/v1/ai/analysis', asyncHandler(async (_request, response) => {
    const [risks, controls, alerts, events] = await Promise.all([RiskAssessment.findAll(), ComplianceControl.findAll(), Alert.findAll(), SecurityEvent.findAll({ limit: 100, order: [['occurred_at', 'DESC']] })]);
    response.json(await analyzeSecurityPosture({ risks: risks.map((item) => item.toJSON()), controls: controls.map((item) => item.toJSON()), alerts: alerts.map((item) => item.toJSON()), events: events.map((item) => item.toJSON()) }));
  }));
  app.get('/api/v1/audit-logs', asyncHandler(async (_request, response) => response.json(await AuditLog.findAll({ limit: 250, order: [['createdAt', 'DESC']] }))));
  app.get('/api/v1/reports/monthly', asyncHandler(async (_request, response) => response.json(await ReportSnapshot.findAll({ attributes: { exclude: ['content_base64'] }, order: [['period', 'DESC']] }))));
  app.get('/api/v1/reports/monthly/:id.pdf', asyncHandler(async (request, response) => { const report = await ReportSnapshot.findByPk(request.params.id); if (!report) throw notFound('Informe mensual no encontrado'); const content = Buffer.from(report.content_base64, 'base64'); response.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': `attachment; filename="informe-${report.period}.pdf"`, 'Content-Length': content.length }); response.send(content); }));
}

export function startAutomation(models) {
  const interval = Math.max(30_000, Number(process.env.AUTOMATION_INTERVAL_MS ?? 60_000));
  const run = async () => {
    try {
      const monitors = await models.Monitor.findAll({ where: { enabled: true, [Op.or]: [{ next_check_at: null }, { next_check_at: { [Op.lte]: new Date() } }] } });
      await Promise.all(monitors.map((monitor) => executeMonitor(models, monitor)));
      const period = new Date().toISOString().slice(0, 7);
      const snapshot = await models.ReportSnapshot.findOne({ where: { period } });
      if (!snapshot || snapshot.report_type !== 'Mensual v3') {
        const content = await buildExecutiveReport(await collectExecutiveReportData(models));
        const payload = { period, report_type: 'Mensual v3', content_base64: content.toString('base64'), size_bytes: content.length, generated_at: new Date() };
        if (snapshot) await snapshot.update(payload); else await models.ReportSnapshot.create(payload);
      }
    } catch (error) { console.error('Error de monitoreo automático:', error); }
  };
  void run();
  const timer = setInterval(run, interval);
  timer.unref();
  return timer;
}
