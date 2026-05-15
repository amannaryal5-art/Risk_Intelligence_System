export interface CaseComment {
  id: number;
  case_id: number;
  author: string;
  message: string;
  created_at: string;
}

export interface RiskCase {
  id: number;
  created_at: string;
  updated_at: string;
  source_type: string;
  source_value: string | null;
  title: string;
  severity: string;
  status: string;
  assigned_to: string | null;
  reporter: string;
  ioc_type: string | null;
  ioc_value: string | null;
  risk_score: number | null;
  findings: Record<string, unknown>;
  scan_result: Record<string, unknown>;
  tags: string[];
  recommendations: string[];
  notes: string | null;
  comments?: CaseComment[];
}

export interface CaseListResponse {
  count: number;
  results: RiskCase[];
}
