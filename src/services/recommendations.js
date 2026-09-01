const rules = {
  PROTECT: ['Reforzar controles preventivos', 'Aplique MFA, mínimo privilegio y endurecimiento de configuración sobre el activo afectado.', 'NIST PR.AA / PR.PS'],
  DETECT: ['Mejorar la detección temprana', 'Centralice registros, defina alertas accionables y mida el tiempo de detección del evento.', 'NIST DE.CM / DE.AE'],
  RESPOND: ['Probar el plan de respuesta', 'Asigne responsables, canales alternos y ejercicios trimestrales para el escenario identificado.', 'NIST RS.MA / RS.CO'],
  RECOVER: ['Validar la recuperación', 'Mantenga copias aisladas y ejecute una restauración documentada del activo crítico.', 'NIST RC.RP / CIS 11'],
  GOVERN: ['Formalizar el gobierno del riesgo', 'Defina propietario, apetito de riesgo, fecha objetivo y evidencia de aceptación o tratamiento.', 'NIST GV.RM / GV.RR'],
  IDENTIFY: ['Completar el análisis de exposición', 'Documente dependencias, flujo de datos y vulnerabilidades para seleccionar controles proporcionales.', 'NIST ID.AM / ID.RA'],
};

export function buildRecommendations(risks) {
  const recommendations = [];
  const usedFunctions = new Set();
  const orderedRisks = [...risks].sort((left, right) => right.score - left.score);
  for (const risk of orderedRisks) {
    const nistFunction = rules[risk.nist_function] ? risk.nist_function : 'IDENTIFY';
    if (usedFunctions.has(nistFunction)) continue;
    const [title, detail, framework] = rules[nistFunction];
    recommendations.push({
      id: `risk-${risk.id}-${nistFunction.toLowerCase()}`,
      title,
      detail: `${detail} Prioridad derivada de: ${risk.title} (${risk.score}/25).`,
      priority: risk.score >= 20 ? 'Crítica' : risk.score >= 12 ? 'Alta' : 'Media',
      framework,
    });
    usedFunctions.add(nistFunction);
    if (recommendations.length === 5) break;
  }
  return recommendations.length > 0 ? recommendations : [{ id: 'baseline-inventory', title: 'Iniciar el inventario institucional', detail: 'Registre activos, responsables y criticidad para habilitar la evaluación de riesgos.', priority: 'Media', framework: 'NIST ID.AM' }];
}
