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

  Asset.hasMany(RiskAssessment, { as: 'risks', foreignKey: 'asset_id', onDelete: 'CASCADE' });
  RiskAssessment.belongsTo(Asset, { as: 'asset', foreignKey: { name: 'asset_id', allowNull: false }, onDelete: 'CASCADE' });

  return { User, Asset, RiskAssessment };
}
