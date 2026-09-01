function deterministicAnalysis({ risks, controls, alerts, events }) {
  const openRisks = risks.filter((item) => !['Mitigado', 'Cerrado'].includes(item.status));
  const failedControls = controls.filter((item) => item.score < 70);
  const urgentAlerts = alerts.filter((item) => ['Crítica', 'Alta'].includes(item.severity) && item.status !== 'Cerrada');
  const exposure = openRisks.reduce((sum, item) => sum + item.score, 0);
  const trend = events.length >= 5 ? 'creciente' : 'estable';
  return {
    mode: 'motor-analitico-local',
    posture: exposure >= 60 ? 'Crítica' : exposure >= 30 ? 'Elevada' : 'Controlada',
    attack_probability: Math.min(95, Math.round(15 + exposure * 0.7 + urgentAlerts.length * 8 + failedControls.length * 2)),
    trend,
    executive_summary: `La exposición se clasifica como ${exposure >= 60 ? 'crítica' : exposure >= 30 ? 'elevada' : 'controlada'}, con ${openRisks.length} riesgos abiertos, ${urgentAlerts.length} alertas prioritarias y ${failedControls.length} controles por fortalecer.`,
    recommendations: [
      urgentAlerts.length ? 'Atender y documentar las alertas críticas o altas antes de aceptar nuevos riesgos.' : 'Mantener vigilancia sobre fuentes de eventos y umbrales de alerta.',
      failedControls.length ? `Priorizar los ${Math.min(failedControls.length, 5)} controles con menor puntuación y adjuntar evidencia.` : 'Conservar evidencia vigente de los controles implementados.',
      openRisks.length ? 'Aplicar tratamiento a los riesgos con mayor probabilidad por impacto.' : 'Realizar una nueva evaluación de riesgos ante cambios de infraestructura.',
    ],
  };
}

function responseText(payload) {
  if (payload.output_text) return payload.output_text;
  return (payload.output ?? []).flatMap((item) => item.content ?? []).find((item) => item.type === 'output_text')?.text;
}

export async function analyzeSecurityPosture(context) {
  const baseline = deterministicAnalysis(context);
  if (!process.env.OPENAI_API_KEY) return baseline;
  const schema = {
    type: 'object', additionalProperties: false,
    required: ['posture', 'attack_probability', 'trend', 'executive_summary', 'recommendations'],
    properties: {
      posture: { type: 'string' }, attack_probability: { type: 'integer', minimum: 0, maximum: 100 }, trend: { type: 'string' }, executive_summary: { type: 'string' }, recommendations: { type: 'array', items: { type: 'string' }, minItems: 3, maxItems: 6 },
    },
  };
  try {
    const response = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST', signal: AbortSignal.timeout(30000),
      headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL ?? 'gpt-5-mini',
        instructions: 'Eres un analista SOC. Analiza exclusivamente los datos proporcionados, no inventes evidencia y devuelve JSON en español.',
        input: JSON.stringify({ ...context, baseline }),
        text: { format: { type: 'json_schema', name: 'security_posture', strict: true, schema } },
      }),
    });
    if (!response.ok) throw new Error(`OpenAI respondió ${response.status}`);
    const parsed = JSON.parse(responseText(await response.json()));
    return { ...parsed, mode: 'openai' };
  } catch (error) {
    return { ...baseline, mode: 'motor-analitico-local', provider_warning: error.message };
  }
}

