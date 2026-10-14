import type {
  ApiKey,
  CreatedApiKey,
  Finding,
  FindingEvent,
  IngestResponse,
  Report,
  RetentionResult,
  Team,
  TeamMember,
  Waiver,
  WaiverCondition,
  WaiverContext,
} from "@/types/api";
import type { components } from "@/types/api.gen";
import { describe, expectTypeOf, it } from "vitest";

type Schemas = components["schemas"];

// Each check runs in both directions. Hand-written -> schema catches a field the
// hand type has that the schema lacks, or a type that is wider than the schema.
// Schema -> hand-written catches a required schema field the hand type is missing,
// or an optional/required mismatch.

describe("hand-written API types match openapi.yaml", () => {
  it("keeps Team in step with the schema", () => {
    expectTypeOf<Team>().toMatchTypeOf<Schemas["Team"]>();
    expectTypeOf<Schemas["Team"]>().toMatchTypeOf<Team>();
  });

  it("keeps TeamMember in step with the schema", () => {
    expectTypeOf<TeamMember>().toEqualTypeOf<Schemas["TeamMember"]>();
  });

  it("keeps ApiKey in step with the schema", () => {
    expectTypeOf<ApiKey>().toEqualTypeOf<Schemas["ApiKey"]>();
  });

  it("keeps CreatedApiKey a narrowing of the schema", () => {
    // The creation response always carries raw_key, so the hand type makes it required.
    expectTypeOf<CreatedApiKey>().toMatchTypeOf<Schemas["ApiKey"]>();
  });

  it("keeps Report in step with the schema", () => {
    // status is typed string here; ReportStatus documents the values the server sends.
    type Keys = "status";
    expectTypeOf<Omit<Report, Keys>>().toMatchTypeOf<Omit<Schemas["Report"], Keys>>();
    expectTypeOf<Omit<Schemas["Report"], Keys>>().toMatchTypeOf<Omit<Report, Keys>>();
  });

  it("keeps IngestResponse in step with the schema", () => {
    expectTypeOf<IngestResponse>().toEqualTypeOf<Schemas["IngestResponse"]>();
  });

  it("keeps RetentionResult in step with the schema", () => {
    expectTypeOf<RetentionResult>().toEqualTypeOf<Schemas["RetentionResult"]>();
  });

  it("keeps FindingEvent in step with the schema", () => {
    expectTypeOf<FindingEvent>().toEqualTypeOf<Schemas["FindingEvent"]>();
  });

  it("keeps Waiver in step with the schema", () => {
    expectTypeOf<Waiver>().toEqualTypeOf<Schemas["Waiver"]>();
  });

  it("keeps WaiverCondition and WaiverContext in step with the schema", () => {
    expectTypeOf<WaiverCondition>().toEqualTypeOf<Schemas["WaiverCondition"]>();
    expectTypeOf<WaiverContext>().toEqualTypeOf<Schemas["WaiverContext"]>();
  });

  it("keeps Finding in step with the schema", () => {
    // The enum-valued fields are typed with the app's own unions (TechnicalState,
    // AnalysisState, Severity, ...), so they are left out of the structural check.
    type Keys = "finding_kind" | "current_severity" | "state" | "analysis_state" | "gate_effect";
    expectTypeOf<Omit<Finding, Keys>>().toMatchTypeOf<Omit<Schemas["Finding"], Keys>>();
    expectTypeOf<Omit<Schemas["Finding"], Keys>>().toMatchTypeOf<Omit<Finding, Keys>>();
  });

  it("documents that the contract is enforced by the type checker", () => {
    // The assertions above fail the type check when a field drifts; this `it` only records the intent.
    expectTypeOf<true>().toEqualTypeOf<true>();
  });
});
