import PDFDocument from 'pdfkit';

import { buildRecommendations } from './recommendations.js';

const palette = {
  navy: '#071526', ink: '#122033', cyan: '#0891b2', cyanDark: '#0e7490', cyanLight: '#ecfeff',
  slate: '#475569', line: '#dbe4ee', surface: '#f8fafc', red: '#dc2626', amber: '#d97706',
  green: '#059669', white: '#ffffff',
};
const severityColors = { Crítico: palette.red, Alto: '#ea580c', Medio: palette.amber, Bajo: palette.green };
const content = { x: 42, width: 511, bottom: 790 };

function valueOf(record, key, fallback = '') { return record?.get ? record.get(key) ?? fallback : record?.[key] ?? fallback; }
function clamp(value, minimum, maximum) { return Math.max(minimum, Math.min(maximum, Number(value) || 0)); }

export async function collectExecutiveReportData(models) {
  const [assets, risks, controls, scans, monitors, alerts, events, incidents, documents] = await Promise.all([
    models.Asset.findAll(),
    models.RiskAssessment.findAll({ include: [{ model: models.Asset, as: 'asset', attributes: ['name'] }] }),
    models.ComplianceControl.findAll(), models.VulnerabilityScan.count(), models.Monitor.findAll(),
    models.Alert.findAll(), models.SecurityEvent.count(), models.Incident.findAll(), models.EvidenceDocument.count(),
  ]);
  const compliance = controls.length ? Math.round(controls.reduce((sum, item) => sum + Number(valueOf(item, 'score', 0)), 0) / controls.length) : 0;
  const actionableRisks = risks.filter((risk) => !['Mitigado', 'Cerrado'].includes(valueOf(risk, 'status')));
  return {
    assets, risks, recommendations: buildRecommendations(actionableRisks),
    metrics: {
      compliance, scans, monitors: monitors.length,
      servicesDown: monitors.filter((item) => valueOf(item, 'status') === 'Caído').length,
      alerts: alerts.filter((item) => valueOf(item, 'status') !== 'Cerrada').length,
      criticalAlerts: alerts.filter((item) => valueOf(item, 'severity') === 'Crítica' && valueOf(item, 'status') !== 'Cerrada').length,
      events, incidents: incidents.filter((item) => valueOf(item, 'status') !== 'Cerrado').length, documents,
    },
  };
}

function drawPageHeader(document, title, subtitle) {
  document.rect(0, 0, document.page.width, 92).fill(palette.navy);
  document.fillColor(palette.white).font('Helvetica-Bold').fontSize(20).text('CiberGuate IA', content.x, 28, { width: 250 });
  document.fillColor('#a5f3fc').font('Helvetica').fontSize(9).text(title, 300, 31, { width: 253, align: 'right' });
  document.fillColor('#cbd5e1').fontSize(8).text(subtitle, 300, 49, { width: 253, align: 'right' });
}

function drawSectionTitle(document, title, subtitle, y) {
  document.fillColor(palette.cyanDark).font('Helvetica-Bold').fontSize(14).text(title, content.x, y, { width: content.width });
  if (subtitle) document.fillColor(palette.slate).font('Helvetica').fontSize(8.5).text(subtitle, content.x, y + 20, { width: content.width });
}

function drawKpi(document, x, y, width, label, value, detail) {
  document.roundedRect(x, y, width, 62, 8).fill(palette.surface).strokeColor(palette.line).lineWidth(0.7).stroke();
  document.fillColor(palette.cyanDark).font('Helvetica-Bold').fontSize(18).text(String(value), x + 12, y + 11, { width: width - 24 });
  document.fillColor(palette.ink).font('Helvetica-Bold').fontSize(8).text(label, x + 12, y + 34, { width: width - 24 });
  document.fillColor(palette.slate).font('Helvetica').fontSize(7).text(detail, x + 12, y + 47, { width: width - 24 });
}

function drawHorizontalChart(document, { x, y, width, height, title, labels, values, maximum, colors }) {
  document.roundedRect(x, y, width, height, 9).fill(palette.white).strokeColor(palette.line).lineWidth(0.7).stroke();
  document.fillColor(palette.ink).font('Helvetica-Bold').fontSize(10).text(title, x + 14, y + 13, { width: width - 28 });
  const max = maximum || Math.max(1, ...values.map(Number));
  const chartTop = y + 40;
  const rowHeight = (height - 52) / Math.max(labels.length, 1);
  labels.forEach((label, index) => {
    const rowY = chartTop + index * rowHeight;
    const numeric = Number(values[index]) || 0;
    document.fillColor(palette.slate).font('Helvetica').fontSize(7).text(label, x + 14, rowY, { width: 78, ellipsis: true });
    document.roundedRect(x + 94, rowY + 1, width - 132, 8, 4).fill('#e2e8f0');
    const barWidth = (width - 132) * clamp(numeric / max, 0, 1);
    if (barWidth > 0) document.roundedRect(x + 94, rowY + 1, barWidth, 8, 4).fill(colors?.[index] ?? palette.cyan);
    document.fillColor(palette.ink).font('Helvetica-Bold').fontSize(7).text(String(numeric), x + width - 33, rowY, { width: 20, align: 'right' });
  });
}

function drawRiskCard(document, risk, index, y) {
  const title = `${index + 1}. ${valueOf(risk, 'title', 'Riesgo sin título')}`;
  const threat = `Amenaza: ${valueOf(risk, 'threat', 'No indicada')}`;
  const notes = valueOf(risk, 'notes', 'Sin notas adicionales');
  const titleHeight = document.font('Helvetica-Bold').fontSize(10).heightOfString(title, { width: 350 });
  const notesHeight = document.font('Helvetica').fontSize(8).heightOfString(notes, { width: 350 });
  const height = Math.max(76, 43 + titleHeight + notesHeight);
  document.roundedRect(content.x, y, content.width, height, 8).fill(palette.white).strokeColor(palette.line).lineWidth(0.7).stroke();
  const level = String(valueOf(risk, 'level', 'Sin nivel'));
  document.roundedRect(content.x + content.width - 94, y + 12, 78, 22, 11).fill(severityColors[level] ?? palette.slate);
  document.fillColor(palette.white).font('Helvetica-Bold').fontSize(8).text(`${level} · ${valueOf(risk, 'score', 0)}/25`, content.x + content.width - 90, y + 19, { width: 70, align: 'center' });
  document.fillColor(palette.ink).font('Helvetica-Bold').fontSize(10).text(title, content.x + 14, y + 13, { width: 350 });
  const assetName = risk.asset?.name ?? valueOf(risk, 'asset_name', 'Sin activo');
  document.fillColor(palette.slate).font('Helvetica').fontSize(8).text(`Activo: ${assetName}   ·   NIST: ${valueOf(risk, 'nist_function', 'N/D')}`, content.x + 14, y + 35 + titleHeight, { width: 470 });
  document.fillColor(palette.slate).fontSize(8).text(threat, content.x + 14, y + 49 + titleHeight, { width: 470 });
  if (notes !== 'Sin notas adicionales') document.fillColor(palette.slate).fontSize(8).text(notes, content.x + 14, y + 62 + titleHeight, { width: 470 });
  return height;
}

function drawActionCard(document, item, index, y) {
  const title = `${index + 1}. ${item.title}`;
  const body = `${item.detail} Marco de referencia: ${item.framework}.`;
  const bodyHeight = document.font('Helvetica').fontSize(8.5).heightOfString(body, { width: 448, lineGap: 2 });
  const height = Math.max(72, bodyHeight + 47);
  document.roundedRect(content.x, y, content.width, height, 8).fill(palette.cyanLight).strokeColor('#a5f3fc').lineWidth(0.7).stroke();
  document.circle(content.x + 22, y + 23, 11).fill(palette.cyanDark);
  document.fillColor(palette.white).font('Helvetica-Bold').fontSize(9).text(String(index + 1), content.x + 15, y + 19, { width: 14, align: 'center' });
  document.fillColor(palette.ink).font('Helvetica-Bold').fontSize(10).text(title, content.x + 44, y + 13, { width: 360 });
  document.roundedRect(content.x + content.width - 91, y + 12, 75, 20, 10).fill(palette.white);
  document.fillColor(palette.cyanDark).font('Helvetica-Bold').fontSize(7.5).text(item.priority, content.x + content.width - 87, y + 18, { width: 67, align: 'center' });
  document.fillColor(palette.slate).font('Helvetica').fontSize(8.5).text(body, content.x + 44, y + 36, { width: 448, lineGap: 2 });
  return height;
}

function drawFooter(document, pageNumber) {
  document.strokeColor(palette.line).lineWidth(0.5).moveTo(content.x, 808).lineTo(content.x + content.width, 808).stroke();
  document.fillColor(palette.slate).font('Helvetica').fontSize(7).text('Uso interno · Evidencia para revisión profesional', content.x, 817, { width: 330 });
  document.fillColor(palette.slate).font('Helvetica').fontSize(7).text(`Página ${pageNumber}`, content.x + 350, 817, { width: 161, align: 'right' });
}

export function buildExecutiveReport({ assets, risks, recommendations, metrics = {} }) {
  return new Promise((resolve, reject) => {
    const document = new PDFDocument({ size: 'A4', margin: 0, info: { Title: 'Informe ejecutivo de seguridad', Author: 'CiberGuate IA', Subject: 'Postura, riesgos y operación de seguridad' } });
    const chunks = [];
    document.on('data', (chunk) => chunks.push(chunk));
    document.on('end', () => resolve(Buffer.concat(chunks)));
    document.on('error', reject);

    const openRisks = risks.filter((risk) => !['Mitigado', 'Cerrado'].includes(valueOf(risk, 'status')));
    const criticalRisks = openRisks.filter((risk) => valueOf(risk, 'level') === 'Crítico');
    const average = risks.length ? risks.reduce((sum, risk) => sum + Number(valueOf(risk, 'score', 0)), 0) / risks.length : 0;
    const generated = new Intl.DateTimeFormat('es-GT', { dateStyle: 'long', timeStyle: 'short', timeZone: 'America/Guatemala' }).format(new Date());
    const riskLevels = ['Crítico', 'Alto', 'Medio', 'Bajo'];
    const riskValues = riskLevels.map((level) => openRisks.filter((risk) => valueOf(risk, 'level') === level).length);
    let pageNumber = 1;
    const startPage = (title, subtitle) => {
      drawFooter(document, pageNumber);
      document.addPage(); pageNumber += 1;
      drawPageHeader(document, title, subtitle);
    };

    drawPageHeader(document, 'Informe ejecutivo de seguridad', `Corte actualizado · ${generated}`);
    drawSectionTitle(document, 'Resumen de postura', 'Indicadores calculados desde los registros vigentes de la plataforma.', 112);
    const kpis = [
      ['Activos', assets.length, `${assets.filter((asset) => Number(valueOf(asset, 'criticality', 0)) >= 4).length} de alta criticidad`],
      ['Riesgos abiertos', openRisks.length, `${criticalRisks.length} críticos`],
      ['Riesgo promedio', `${average.toFixed(1)}/25`, 'Probabilidad por impacto'],
      ['Cumplimiento', `${metrics.compliance ?? 0}%`, 'Controles evaluados'],
      ['Alertas abiertas', metrics.alerts ?? 0, `${metrics.criticalAlerts ?? 0} críticas`],
      ['Incidentes abiertos', metrics.incidents ?? 0, `${metrics.servicesDown ?? 0} servicios caídos`],
    ];
    kpis.forEach(([label, value, detail], index) => drawKpi(document, content.x + (index % 3) * 174, 153 + Math.floor(index / 3) * 74, 163, label, value, detail));
    drawSectionTitle(document, 'Métricas consolidadas', 'La escala y el valor exacto se muestran en cada barra.', 313);
    drawHorizontalChart(document, { x: content.x, y: 350, width: 248, height: 218, title: 'Riesgos abiertos por nivel', labels: riskLevels, values: riskValues, colors: riskLevels.map((level) => severityColors[level]) });
    drawHorizontalChart(document, { x: 305, y: 350, width: 248, height: 218, title: 'Operación de seguridad', labels: ['Diagnósticos', 'Monitores', 'Alertas', 'Eventos', 'Incidentes', 'Documentos'], values: [metrics.scans ?? 0, metrics.monitors ?? 0, metrics.alerts ?? 0, metrics.events ?? 0, metrics.incidents ?? 0, metrics.documents ?? 0] });
    document.roundedRect(content.x, 590, content.width, 150, 9).fill(palette.navy);
    document.fillColor('#67e8f9').font('Helvetica-Bold').fontSize(9).text('LECTURA EJECUTIVA', content.x + 18, 609, { width: 180 });
    const posture = criticalRisks.length > 0 ? 'Atención prioritaria' : openRisks.length > 0 ? 'Exposición controlable' : 'Sin riesgos abiertos';
    document.fillColor(palette.white).font('Helvetica-Bold').fontSize(22).text(posture, content.x + 18, 632, { width: 475 });
    document.fillColor('#cbd5e1').font('Helvetica').fontSize(9.5).text(`La organización registra ${openRisks.length} riesgos abiertos y ${metrics.alerts ?? 0} alertas activas. El cumplimiento consolidado es ${metrics.compliance ?? 0}%. Las decisiones deben basarse en el detalle y plan de acción de las páginas siguientes.`, content.x + 18, 670, { width: 475, lineGap: 3 });

    startPage('Riesgos prioritarios', 'Ordenados por puntaje inherente de mayor a menor');
    drawSectionTitle(document, 'Detalle verificable', 'Cada registro conserva activo, amenaza, nivel y función NIST.', 112);
    let y = 153;
    [...openRisks].sort((a, b) => Number(valueOf(b, 'score', 0)) - Number(valueOf(a, 'score', 0))).slice(0, 10).forEach((risk, index) => {
      document.font('Helvetica-Bold').fontSize(10);
      const estimate = Math.max(76, 54 + document.heightOfString(String(valueOf(risk, 'title')), { width: 350 }));
      if (y + estimate > content.bottom) {
        startPage('Riesgos prioritarios', 'Continuación del detalle');
        y = 116;
      }
      y += drawRiskCard(document, risk, index, y) + 10;
    });
    if (openRisks.length === 0) document.fillColor(palette.slate).font('Helvetica').fontSize(11).text('No hay riesgos abiertos para este corte.', content.x, y, { width: content.width });

    startPage('Plan de tratamiento', 'Acciones sugeridas según prioridad y marco de referencia');
    drawSectionTitle(document, 'Acciones recomendadas', 'Valide responsable, fecha objetivo y evidencia antes de cerrar cada acción.', 112);
    y = 153;
    recommendations.forEach((item, index) => {
      document.font('Helvetica').fontSize(8.5);
      const estimate = Math.max(72, document.heightOfString(`${item.detail} ${item.framework}`, { width: 448, lineGap: 2 }) + 47);
      if (y + estimate > 690) {
        startPage('Plan de tratamiento', 'Continuación de acciones recomendadas');
        y = 116;
      }
      y += drawActionCard(document, item, index, y) + 10;
    });
    const methodY = Math.max(y + 10, 620);
    document.roundedRect(content.x, methodY, content.width, 118, 8).fill(palette.surface).strokeColor(palette.line).lineWidth(0.7).stroke();
    document.fillColor(palette.ink).font('Helvetica-Bold').fontSize(10).text('Metodología y alcance', content.x + 14, methodY + 14, { width: 470 });
    document.fillColor(palette.slate).font('Helvetica').fontSize(8).text('Riesgo inherente = probabilidad x impacto, escala 1-25. La distribución incluye riesgos cuyo estado no es Mitigado ni Cerrado. Las métricas operativas corresponden al estado actual de PostgreSQL. Este informe apoya la toma de decisiones y no sustituye una auditoría, un pentest ni la validación humana de las recomendaciones.', content.x + 14, methodY + 35, { width: 470, lineGap: 3 });

    drawFooter(document, pageNumber);
    document.end();
  });
}
