'use strict';

const {
  GraphQLSchema, GraphQLObjectType, GraphQLString, GraphQLInt, GraphQLList,
  GraphQLNonNull, GraphQLBoolean,
} = require('graphql');

const { scanProject } = require('./projectScanner');
const { buildForensicReport } = require('./reportExporter');
const { runScenario, SIMULATORS } = require('./attackSimulator');

// --- Types -------------------------------------------------------------

const CweType = new GraphQLObjectType({
  name: 'Cwe',
  fields: {
    id: { type: GraphQLString },
    name: { type: GraphQLString },
    url: { type: GraphQLString },
  },
});

const FindingType = new GraphQLObjectType({
  name: 'Finding',
  fields: {
    id: { type: GraphQLString },
    category: { type: GraphQLString },
    type: { type: GraphQLString },
    severity: { type: GraphQLString },
    title: { type: GraphQLString },
    description: { type: GraphQLString },
    remediation: { type: GraphQLString },
    filePath: { type: GraphQLString },
    resourcePath: { type: GraphQLString },
    lineNumber: { type: GraphQLInt },
    lineText: { type: GraphQLString },
    cwe: { type: CweType },
  },
});

const SeverityCountsType = new GraphQLObjectType({
  name: 'SeverityCounts',
  fields: {
    CRITICAL: { type: GraphQLInt },
    HIGH: { type: GraphQLInt },
    MEDIUM: { type: GraphQLInt },
    LOW: { type: GraphQLInt },
  },
});

const ScanResultType = new GraphQLObjectType({
  name: 'ScanResult',
  fields: {
    projectDir: { type: GraphQLString },
    filesScanned: { type: GraphQLInt },
    gdFilesScanned: { type: GraphQLInt },
    totalFindings: { type: GraphQLInt },
    bySeverity: { type: SeverityCountsType },
    findings: {
      type: new GraphQLList(FindingType),
      args: { severity: { type: GraphQLString } },
      resolve: (report, args) => {
        if (!args.severity) return report.findings;
        return report.findings.filter((f) => f.severity === args.severity);
      },
    },
  },
});

const ScenarioResultType = new GraphQLObjectType({
  name: 'ScenarioResult',
  fields: {
    scenarioName: { type: GraphQLString },
    simulationMode: { type: GraphQLBoolean },
    resultJson: {
      type: GraphQLString,
      description: 'The full simulated result, JSON-encoded (shape varies by scenario).',
      resolve: (payload) => JSON.stringify(payload.result || payload.results || payload),
    },
    error: { type: GraphQLString },
  },
});

// --- Query / Mutation ----------------------------------------------------

const QueryType = new GraphQLObjectType({
  name: 'Query',
  fields: {
    health: {
      type: GraphQLString,
      resolve: () => 'ok',
    },
    scenarios: {
      type: new GraphQLList(GraphQLString),
      resolve: () => SIMULATORS.concat(['full_stack_attack']),
    },
    scan: {
      type: ScanResultType,
      description: 'Scans a project directory and returns a full forensic report.',
      args: { projectDir: { type: new GraphQLNonNull(GraphQLString) } },
      resolve: (_, { projectDir }) => {
        const result = scanProject(projectDir);
        const report = buildForensicReport(result.codeFindings, result.resourceFindings);
        return {
          projectDir: result.projectDir,
          filesScanned: result.filesScanned,
          gdFilesScanned: result.gdFilesScanned,
          totalFindings: report.summary.totalFindings,
          bySeverity: report.summary.bySeverity,
          findings: report.findings,
        };
      },
    },
  },
});

const MutationType = new GraphQLObjectType({
  name: 'Mutation',
  fields: {
    runScenario: {
      type: ScenarioResultType,
      description: 'Runs a simulated attack scenario. Never touches a real target — see attackSimulator.js.',
      args: {
        name: { type: new GraphQLNonNull(GraphQLString) },
        target: { type: GraphQLString },
        payload: { type: GraphQLString },
      },
      resolve: (_, { name, target, payload }) => runScenario(name, { target, payload }),
    },
  },
});

const schema = new GraphQLSchema({ query: QueryType, mutation: MutationType });

module.exports = { schema };
