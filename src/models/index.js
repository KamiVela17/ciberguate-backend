import { DataTypes } from 'sequelize';

export function defineModels(database) {
  const User = database.define('users', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    email: { type: DataTypes.STRING(180), allowNull: false, unique: true, validate: { isEmail: true } },
    password_hash: { type: DataTypes.STRING(100), allowNull: false },
    display_name: { type: DataTypes.STRING(120), allowNull: false },
    role: { type: DataTypes.STRING(30), allowNull: false, defaultValue: 'admin' },
  });

  const Asset = database.define('assets', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    name: { type: DataTypes.STRING(180), allowNull: false, validate: { len: [2, 180] } },
    asset_type: { type: DataTypes.STRING(80), allowNull: false },
    owner: { type: DataTypes.STRING(120), allowNull: false },
    location: { type: DataTypes.STRING(180), allowNull: false },
    criticality: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 3, validate: { min: 1, max: 5 } },
    status: { type: DataTypes.STRING(40), allowNull: false, defaultValue: 'Activo' },
    description: { type: DataTypes.TEXT, allowNull: true },
  });

  const RiskAssessment = database.define('risk_assessments', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    title: { type: DataTypes.STRING(180), allowNull: false, validate: { len: [2, 180] } },
    threat: { type: DataTypes.STRING(180), allowNull: false },
    likelihood: { type: DataTypes.INTEGER, allowNull: false, validate: { min: 1, max: 5 } },
    impact: { type: DataTypes.INTEGER, allowNull: false, validate: { min: 1, max: 5 } },
    score: { type: DataTypes.INTEGER, allowNull: false },
    level: { type: DataTypes.STRING(30), allowNull: false },
    status: { type: DataTypes.STRING(40), allowNull: false, defaultValue: 'Abierto' },
    nist_function: {
      type: DataTypes.STRING(30), allowNull: false, defaultValue: 'IDENTIFY',
      validate: { isIn: [['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER']] },
    },
    notes: { type: DataTypes.TEXT, allowNull: true },
  });

  const ComplianceControl = database.define('compliance_controls', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    framework: { type: DataTypes.STRING(40), allowNull: false },
    code: { type: DataTypes.STRING(60), allowNull: false },
    title: { type: DataTypes.STRING(220), allowNull: false },
    description: { type: DataTypes.TEXT, allowNull: true },
    status: { type: DataTypes.STRING(30), allowNull: false, defaultValue: 'Pendiente' },
    score: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0, validate: { min: 0, max: 100 } },
    evidence: { type: DataTypes.TEXT, allowNull: true },
    owner: { type: DataTypes.STRING(120), allowNull: true },
    reviewed_at: { type: DataTypes.DATE, allowNull: true },
  }, { indexes: [{ unique: true, fields: ['framework', 'code'] }] });

  const VulnerabilityScan = database.define('vulnerability_scans', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    target: { type: DataTypes.STRING(500), allowNull: false },
    status: { type: DataTypes.STRING(30), allowNull: false, defaultValue: 'Pendiente' },
    risk_score: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    findings_count: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    summary: { type: DataTypes.TEXT, allowNull: true },
    findings: { type: DataTypes.JSONB, allowNull: false, defaultValue: [] },
    started_at: { type: DataTypes.DATE, allowNull: true },
    completed_at: { type: DataTypes.DATE, allowNull: true },
  });

  const Monitor = database.define('monitors', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    name: { type: DataTypes.STRING(180), allowNull: false },
    target: { type: DataTypes.STRING(500), allowNull: false },
    interval_minutes: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 5, validate: { min: 1, max: 1440 } },
    enabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
    status: { type: DataTypes.STRING(30), allowNull: false, defaultValue: 'Sin verificar' },
    availability_percentage: { type: DataTypes.FLOAT, allowNull: false, defaultValue: 100 },
    checks_total: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    checks_successful: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    latency_ms: { type: DataTypes.INTEGER, allowNull: true },
    last_checked_at: { type: DataTypes.DATE, allowNull: true },
    next_check_at: { type: DataTypes.DATE, allowNull: true },
  });

  const Alert = database.define('alerts', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    title: { type: DataTypes.STRING(220), allowNull: false },
    severity: { type: DataTypes.STRING(30), allowNull: false, defaultValue: 'Media' },
    status: { type: DataTypes.STRING(30), allowNull: false, defaultValue: 'Nueva' },
    source: { type: DataTypes.STRING(80), allowNull: false },
    details: { type: DataTypes.TEXT, allowNull: true },
    detected_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    acknowledged_at: { type: DataTypes.DATE, allowNull: true },
  });

  const EvidenceDocument = database.define('evidence_documents', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    name: { type: DataTypes.STRING(220), allowNull: false },
    category: { type: DataTypes.STRING(80), allowNull: false, defaultValue: 'Evidencia' },
    mime_type: { type: DataTypes.STRING(120), allowNull: false, defaultValue: 'text/plain' },
    content: { type: DataTypes.TEXT, allowNull: false },
    size_bytes: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    uploaded_by: { type: DataTypes.STRING(180), allowNull: false },
  });

  const SecurityEvent = database.define('security_events', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    source: { type: DataTypes.STRING(120), allowNull: false },
    event_type: { type: DataTypes.STRING(120), allowNull: false },
    severity: { type: DataTypes.STRING(30), allowNull: false, defaultValue: 'Informativa' },
    description: { type: DataTypes.TEXT, allowNull: false },
    raw_data: { type: DataTypes.JSONB, allowNull: false, defaultValue: {} },
    occurred_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
  });

  const Incident = database.define('incidents', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    title: { type: DataTypes.STRING(220), allowNull: false },
    severity: { type: DataTypes.STRING(30), allowNull: false, defaultValue: 'Media' },
    status: { type: DataTypes.STRING(40), allowNull: false, defaultValue: 'Abierto' },
    description: { type: DataTypes.TEXT, allowNull: false },
    assigned_to: { type: DataTypes.STRING(180), allowNull: true },
    playbook: { type: DataTypes.STRING(120), allowNull: false, defaultValue: 'Contención estándar' },
    contained_at: { type: DataTypes.DATE, allowNull: true },
    closed_at: { type: DataTypes.DATE, allowNull: true },
  });

  const AutomatedAction = database.define('automated_actions', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    action_type: { type: DataTypes.STRING(120), allowNull: false },
    status: { type: DataTypes.STRING(30), allowNull: false, defaultValue: 'Ejecutada' },
    details: { type: DataTypes.TEXT, allowNull: false },
    executed_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
  });

  const AuditLog = database.define('audit_logs', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    actor: { type: DataTypes.STRING(180), allowNull: false },
    action: { type: DataTypes.STRING(120), allowNull: false },
    resource: { type: DataTypes.STRING(180), allowNull: false },
    ip_address: { type: DataTypes.STRING(80), allowNull: true },
    metadata: { type: DataTypes.JSONB, allowNull: false, defaultValue: {} },
  });

  const ReportSnapshot = database.define('report_snapshots', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    period: { type: DataTypes.STRING(7), allowNull: false, unique: true },
    report_type: { type: DataTypes.STRING(60), allowNull: false, defaultValue: 'Mensual' },
    content_base64: { type: DataTypes.TEXT, allowNull: false },
    size_bytes: { type: DataTypes.INTEGER, allowNull: false },
    generated_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
  });

  const MfaSetting = database.define('mfa_settings', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    secret: { type: DataTypes.STRING(80), allowNull: false },
    enabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    recovery_codes: { type: DataTypes.JSONB, allowNull: false, defaultValue: [] },
  });

  Asset.hasMany(RiskAssessment, { as: 'risks', foreignKey: 'asset_id', onDelete: 'CASCADE' });
  RiskAssessment.belongsTo(Asset, { as: 'asset', foreignKey: { name: 'asset_id', allowNull: false }, onDelete: 'CASCADE' });

  Asset.hasMany(VulnerabilityScan, { as: 'scans', foreignKey: 'asset_id', onDelete: 'SET NULL' });
  VulnerabilityScan.belongsTo(Asset, { as: 'asset', foreignKey: { name: 'asset_id', allowNull: true }, onDelete: 'SET NULL' });
  Asset.hasMany(Monitor, { as: 'monitors', foreignKey: 'asset_id', onDelete: 'SET NULL' });
  Monitor.belongsTo(Asset, { as: 'asset', foreignKey: { name: 'asset_id', allowNull: true }, onDelete: 'SET NULL' });
  Asset.hasMany(Alert, { as: 'alerts', foreignKey: 'asset_id', onDelete: 'SET NULL' });
  Alert.belongsTo(Asset, { as: 'asset', foreignKey: { name: 'asset_id', allowNull: true }, onDelete: 'SET NULL' });
  Asset.hasMany(SecurityEvent, { as: 'security_events', foreignKey: 'asset_id', onDelete: 'SET NULL' });
  SecurityEvent.belongsTo(Asset, { as: 'asset', foreignKey: { name: 'asset_id', allowNull: true }, onDelete: 'SET NULL' });
  Asset.hasMany(Incident, { as: 'incidents', foreignKey: 'asset_id', onDelete: 'SET NULL' });
  Incident.belongsTo(Asset, { as: 'asset', foreignKey: { name: 'asset_id', allowNull: true }, onDelete: 'SET NULL' });
  Incident.hasMany(AutomatedAction, { as: 'actions', foreignKey: 'incident_id', onDelete: 'CASCADE' });
  AutomatedAction.belongsTo(Incident, { as: 'incident', foreignKey: { name: 'incident_id', allowNull: false }, onDelete: 'CASCADE' });
  User.hasOne(MfaSetting, { as: 'mfa', foreignKey: 'user_id', onDelete: 'CASCADE' });
  MfaSetting.belongsTo(User, { as: 'user', foreignKey: { name: 'user_id', allowNull: false }, onDelete: 'CASCADE' });

  return { User, Asset, RiskAssessment, ComplianceControl, VulnerabilityScan, Monitor, Alert, EvidenceDocument, SecurityEvent, Incident, AutomatedAction, AuditLog, MfaSetting, ReportSnapshot };
}
