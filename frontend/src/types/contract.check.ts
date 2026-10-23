import type {
  ApiKey,
  CreatedApiKey,
  Finding,
  FindingEvent,
  IngestResponse,
  ProjectStats,
  Report,
  RetentionResult,
  Team,
  TeamMember,
  Waiver,
  WaiverCondition,
  WaiverContext,
} from "@/types/api";
import type { components } from "@/types/api.gen";
import { expectTypeOf } from "vitest";

type Schemas = components["schemas"];

/**
 * Compile-time guard: the hand-written API types must agree with the types generated from
 * openapi.yaml. Nothing imports this file and nothing runs it; `tsc -b` type-checks it, so a
 * field that drifts fails the build. (It is not a .test file because the app's tsconfig leaves
 * those out of the type check.)
 */

// Each check runs in both directions. Hand-written -> schema catches a field the
// hand type has that the schema lacks, or a type that is wider than the schema.
// Schema -> hand-written catches a required schema field the hand type is missing,
// or an optional/required mismatch.

// keeps Team in step with the schema
{
  expectTypeOf<Team>().toMatchTypeOf<Schemas["Team"]>();
  expectTypeOf<Schemas["Team"]>().toMatchTypeOf<Team>();
}

// keeps TeamMember in step with the schema
{
  expectTypeOf<TeamMember>().toEqualTypeOf<Schemas["TeamMember"]>();
}

// keeps ApiKey in step with the schema
{
  expectTypeOf<ApiKey>().toEqualTypeOf<Schemas["ApiKey"]>();
}

// keeps CreatedApiKey a narrowing of the schema
{
  // The creation response always carries raw_key, so the hand type makes it required.
  expectTypeOf<CreatedApiKey>().toMatchTypeOf<Schemas["ApiKey"]>();
}

// keeps Report in step with the schema
{
  // status is typed string here; ReportStatus documents the values the server sends.
  type Keys = "status";
  expectTypeOf<Omit<Report, Keys>>().toMatchTypeOf<Omit<Schemas["Report"], Keys>>();
  expectTypeOf<Omit<Schemas["Report"], Keys>>().toMatchTypeOf<Omit<Report, Keys>>();
}

// keeps the completed-report stats field in step with the schema
{
  type Completed = NonNullable<ProjectStats["latest_completed_report"]>;
  type SchemaCompleted = NonNullable<Schemas["ProjectStats"]["latest_completed_report"]>;
  expectTypeOf<Omit<Completed, "status">>().toMatchTypeOf<Omit<SchemaCompleted, "status">>();
  expectTypeOf<Omit<SchemaCompleted, "status">>().toMatchTypeOf<Omit<Completed, "status">>();
}

// keeps IngestResponse in step with the schema
{
  expectTypeOf<IngestResponse>().toEqualTypeOf<Schemas["IngestResponse"]>();
}

// keeps RetentionResult in step with the schema
{
  expectTypeOf<RetentionResult>().toEqualTypeOf<Schemas["RetentionResult"]>();
}

// keeps FindingEvent in step with the schema
{
  expectTypeOf<FindingEvent>().toEqualTypeOf<Schemas["FindingEvent"]>();
}

// keeps Waiver in step with the schema
{
  expectTypeOf<Waiver>().toEqualTypeOf<Schemas["Waiver"]>();
}

// keeps WaiverCondition and WaiverContext in step with the schema
{
  expectTypeOf<WaiverCondition>().toEqualTypeOf<Schemas["WaiverCondition"]>();
  expectTypeOf<WaiverContext>().toEqualTypeOf<Schemas["WaiverContext"]>();
}

// keeps Finding in step with the schema
{
  // The enum-valued fields are typed with the app's own unions (TechnicalState,
  // AnalysisState, Severity, ...), so they are left out of the structural check.
  type Keys = "finding_kind" | "current_severity" | "state" | "analysis_state" | "gate_effect";
  expectTypeOf<Omit<Finding, Keys>>().toMatchTypeOf<Omit<Schemas["Finding"], Keys>>();
  expectTypeOf<Omit<Schemas["Finding"], Keys>>().toMatchTypeOf<Omit<Finding, Keys>>();
}
