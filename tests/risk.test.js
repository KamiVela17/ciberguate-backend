import { describe, expect, it } from 'vitest';

import { buildRecommendations } from '../src/services/recommendations.js';
import { calculateRisk, normalizeNistFunction } from '../src/services/risk.js';

describe('motor de evaluación', () => {
  it.each([
    [1, 1, 1, 'Bajo'], [2, 3, 6, 'Medio'], [3, 4, 12, 'Alto'], [5, 4, 20, 'Crítico'],
  ])('calcula %i x %i como %i %s', (likelihood, impact, score, level) => {
    expect(calculateRisk(likelihood, impact)).toEqual({ likelihood, impact, score, level });
  });

  it('rechaza valores y funciones NIST inválidas', () => {
    expect(() => calculateRisk(0, 6)).toThrow(/entre 1 y 5/);
    expect(() => normalizeNistFunction('UNKNOWN')).toThrow(/no válida/);
  });

  it('prioriza recomendaciones por puntaje y función', () => {
    const result = buildRecommendations([
      { id: 1, title: 'Ransomware', score: 25, nist_function: 'RECOVER' },
      { id: 2, title: 'Acceso indebido', score: 16, nist_function: 'PROTECT' },
    ]);
    expect(result[0]).toMatchObject({ priority: 'Crítica', framework: 'NIST RC.RP / CIS 11' });
    expect(result[1]).toMatchObject({ priority: 'Alta', framework: 'NIST PR.AA / PR.PS' });
  });
});
