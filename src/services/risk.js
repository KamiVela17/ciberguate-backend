export const NIST_FUNCTIONS = new Set(['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER']);

export function calculateRisk(likelihood, impact) {
  const probabilityValue = Number(likelihood);
  const impactValue = Number(impact);
  if (![probabilityValue, impactValue].every((value) => Number.isInteger(value) && value >= 1 && value <= 5)) {
    const error = new Error('Probabilidad e impacto deben ser enteros entre 1 y 5');
    error.status = 400;
    throw error;
  }
  const score = probabilityValue * impactValue;
  const level = score >= 20 ? 'Crítico' : score >= 12 ? 'Alto' : score >= 6 ? 'Medio' : 'Bajo';
  return { likelihood: probabilityValue, impact: impactValue, score, level };
}

export function normalizeNistFunction(value = 'IDENTIFY') {
  const normalized = String(value).toUpperCase();
  if (!NIST_FUNCTIONS.has(normalized)) {
    const error = new Error('Función NIST no válida');
    error.status = 400;
    throw error;
  }
  return normalized;
}
