import type { components } from "@/types/api.gen";

/** The CVE evaluation details of a finding, straight from the generated API types. */
type Schemas = components["schemas"];

export type CveDetail = Schemas["CveDetail"];
export type CveCvss = Schemas["CveCvss"];
export type CvssMetric = Schemas["CvssMetric"];
export type CveProvenance = Schemas["CveProvenance"];
export type CveEpss = Schemas["CveEpss"];
export type CveKev = Schemas["CveKev"];
export type CveCwe = Schemas["CveCwe"];
export type CveDate = Schemas["CveDate"];
export type CveReference = Schemas["CveReference"];
export type CveProviderLookup = Schemas["CveProviderLookup"];
