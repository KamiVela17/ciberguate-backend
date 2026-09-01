import PDFDocument from 'pdfkit';

const colors = { navy: '#071526', cyan: '#0e7490', muted: '#475569', light: '#ecfeff' };

function ensureSpace(document, required = 80) {
  if (document.y + required > document.page.height - 55) document.addPage();
}

export function buildExecutiveReport(assets, risks, recommendations) {
  return new Promise((resolve, reject) => {
    const document = new PDFDocument({ size: 'A4', margin: 48, info: { Title: 'Informe ejecutivo de riesgos', Author: 'CiberGuate IA' } });
    const chunks = [];
    document.on('data', (chunk) => chunks.push(chunk));
    document.on('end', () => resolve(Buffer.concat(chunks)));
    document.on('error', reject);

    const openRisks = risks.filter((risk) => !['Mitigado', 'Cerrado'].includes(risk.status));
    const criticalRisks = openRisks.filter((risk) => risk.level === 'Crítico');
    const average = risks.length ? risks.reduce((sum, risk) => sum + risk.score, 0) / risks.length : 0;

    document.fillColor(colors.navy).fontSize(25).font('Helvetica-Bold').text('CiberGuate IA', { align: 'center' });
    document.moveDown(0.25).fontSize(14).font('Helvetica').fillColor(colors.muted).text('Informe ejecutivo de exposición y tratamiento de riesgos', { align: 'center' });
    document.moveDown(1.2).roundedRect(48, document.y, 499, 70, 8).fill(colors.light);
    const summaryY = document.y + 15;
    const summary = [['Activos', assets.length], ['Críticos', assets.filter((asset) => asset.criticality >= 4).length], ['Riesgos abiertos', openRisks.length], ['Riesgos críticos', criticalRisks.length], ['Promedio', `${average.toFixed(1)}/25`]];
    summary.forEach(([label, value], index) => {
      const x = 58 + index * 98;
      document.fillColor(colors.navy).font('Helvetica-Bold').fontSize(16).text(String(value), x, summaryY, { width: 88, align: 'center' });
      document.fillColor(colors.muted).font('Helvetica').fontSize(8).text(String(label), x, summaryY + 23, { width: 88, align: 'center' });
    });
    document.y = summaryY + 65;

    document.moveDown().fillColor(colors.cyan).font('Helvetica-Bold').fontSize(15).text('Riesgos prioritarios');
    document.moveDown(0.4);
    [...risks].sort((a, b) => b.score - a.score).slice(0, 10).forEach((risk, index) => {
      ensureSpace(document);
      document.fillColor(colors.navy).font('Helvetica-Bold').fontSize(10).text(`${index + 1}. ${risk.title} - ${risk.score}/25 (${risk.level})`);
      document.fillColor(colors.muted).font('Helvetica').fontSize(9).text(`Activo: ${risk.asset?.name ?? 'Sin activo'} | Amenaza: ${risk.threat} | NIST: ${risk.nist_function}`);
      document.moveDown(0.5);
    });

    ensureSpace(document, 120);
    document.moveDown().fillColor(colors.cyan).font('Helvetica-Bold').fontSize(15).text('Plan de acción recomendado');
    document.moveDown(0.4);
    recommendations.forEach((item, index) => {
      ensureSpace(document, 75);
      document.fillColor(colors.navy).font('Helvetica-Bold').fontSize(10).text(`${index + 1}. ${item.title} - ${item.priority}`);
      document.fillColor(colors.muted).font('Helvetica').fontSize(9).text(`${item.detail} (${item.framework})`, { lineGap: 2 });
      document.moveDown(0.6);
    });

    ensureSpace(document, 70);
    document.moveDown().fillColor(colors.muted).font('Helvetica-Oblique').fontSize(8).text('Metodología: puntaje inherente = probabilidad x impacto (escala 1-25). Priorización alineada con NIST CSF 2.0.');
    document.end();
  });
}
