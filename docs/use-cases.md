# Casos de uso

## Mapa funcional

```mermaid
flowchart LR
    ADMIN[Administrador] --> ID[Administrar identidad y MFA]
    ADMIN --> INV[Gestionar inventario]
    ANALYST[Analista] --> RISK[Evaluar riesgos]
    ANALYST --> SCAN[Diagnosticar objetivo autorizado]
    ANALYST --> SOC[Registrar eventos e incidentes]
    ANALYST --> RESP[Ejecutar respuesta]
    AUDITOR[Auditor] --> COMP[Evaluar cumplimiento]
    AUDITOR --> DOC[Gestionar evidencia]
    AUDITOR --> REP[Generar reportes]
```

## UC-01 Registrar activo

1. Un usuario autenticado envía nombre, tipo, propietario, ubicación y criticidad.
2. La API valida el rango de criticidad y persiste el activo.
3. Registra `ASSET_CREATED` en auditoría.
4. Devuelve el recurso con identificador.

## UC-02 Evaluar riesgo

1. El usuario selecciona un activo y registra amenaza, probabilidad e impacto.
2. El servicio calcula `score` y nivel, y normaliza la función NIST.
3. Persiste la evaluación y el evento de auditoría.
4. Dashboard y recomendaciones incorporan el nuevo resultado.

## UC-03 Ejecutar diagnóstico

```mermaid
sequenceDiagram
    actor A as Analista
    participant API as API
    participant S as Scanner seguro
    participant T as Objetivo autorizado
    participant DB as PostgreSQL
    A->>API: POST /scans
    API->>S: Validar objetivo
    S->>S: Bloquear destino privado/local
    S->>T: Solicitud HTTP/TLS no intrusiva
    T-->>S: Respuesta y encabezados
    S-->>API: Puntaje, resumen y hallazgos
    API->>DB: Persiste ejecución
    API-->>A: Resultado verificable
```

## UC-04 Evaluar cumplimiento

La evaluación automática correlaciona la evidencia disponible con controles. El usuario puede revisar estado, puntaje, responsable y evidencia. Toda actualización conserva fecha de revisión y auditoría.

## UC-05 Responder a incidente

```mermaid
sequenceDiagram
    actor A as Analista
    participant API as API
    participant DB as PostgreSQL
    A->>API: Crea incidente
    API->>DB: Estado Abierto
    A->>API: POST /incidents/:id/respond
    API->>DB: Registra acción automatizada
    API->>DB: Actualiza estado y auditoría
    API-->>A: Incidente con acciones
```

Las acciones de la versión actual son registros de playbook dentro de la plataforma; integrar aislamiento real, firewall o EDR requiere conectores autorizados adicionales.

## UC-06 Emitir evidencia

El usuario consulta el historial, genera/descarga PDF y contrasta período, totales y detalle. Los snapshots mensuales permiten reproducibilidad posterior.
