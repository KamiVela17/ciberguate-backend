# Modelo de datos

## Diagrama entidad-relación

```mermaid
erDiagram
    USER ||--o| MFA_SETTING : configura
    ASSET ||--o{ RISK_ASSESSMENT : posee
    ASSET ||--o{ VULNERABILITY_SCAN : evalua
    ASSET ||--o{ MONITOR : supervisa
    ASSET ||--o{ ALERT : genera
    ASSET ||--o{ SECURITY_EVENT : origina
    ASSET ||--o{ INCIDENT : afecta
    INCIDENT ||--o{ AUTOMATED_ACTION : ejecuta

    USER { int id PK string email string role }
    MFA_SETTING { int id PK int user_id FK boolean enabled }
    ASSET { int id PK string name int criticality string status }
    RISK_ASSESSMENT { int id PK int asset_id FK int score string level }
    VULNERABILITY_SCAN { int id PK int asset_id FK int risk_score json findings }
    MONITOR { int id PK int asset_id FK string target float availability }
    ALERT { int id PK int asset_id FK string severity string status }
    SECURITY_EVENT { int id PK int asset_id FK string event_type json raw_data }
    INCIDENT { int id PK int asset_id FK string severity string status }
    AUTOMATED_ACTION { int id PK int incident_id FK string action_type string status }
```

Entidades independientes: `ComplianceControl`, `EvidenceDocument`, `AuditLog` y `ReportSnapshot`.

## Catálogo

| Entidad | Finalidad | Retención recomendada |
| --- | --- | --- |
| User / MfaSetting | Identidad local y segundo factor | Mientras la cuenta esté activa |
| Asset | Inventario y criticidad | Vida del activo más auditoría |
| RiskAssessment | Riesgo inherente/evaluado | Histórico anual o política aplicable |
| VulnerabilityScan | Resultado y hallazgos JSONB | Según plan y requisito de auditoría |
| Monitor / Alert | Disponibilidad y excepciones | Ventana operativa definida |
| ComplianceControl | Estado de marcos normativos | Al menos un ciclo de auditoría |
| EvidenceDocument | Evidencia almacenada | Política documental y legal |
| SecurityEvent | Eventos SOC/SIEM | Según capacidad y regulación |
| Incident / AutomatedAction | Respuesta y acciones | Política de incidentes |
| AuditLog | Actor, acción, recurso, IP y metadatos | Inmutable durante período normativo |
| ReportSnapshot | PDF mensual en base64 | Según plan de reportes |

## Ciclo del incidente

```mermaid
stateDiagram-v2
    [*] --> Abierto
    Abierto --> EnInvestigacion
    EnInvestigacion --> Contenido
    Contenido --> Cerrado
    Abierto --> Contenido: playbook de respuesta
    Cerrado --> [*]
```

## Integridad

- Eliminar un activo elimina sus riesgos; diagnósticos, monitores, alertas, eventos e incidentes conservan su registro con referencia nula.
- Eliminar un incidente elimina sus acciones; eliminar un usuario elimina su configuración MFA.
- `framework + code` es único en cumplimiento y `period` es único en reportes mensuales.
- `JSONB` conserva hallazgos y datos crudos, pero exige validación y límites en la capa de aplicación.
