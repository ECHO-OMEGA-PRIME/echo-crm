-- Echo CRM v1.0.0 Schema

CREATE TABLE IF NOT EXISTS pipelines (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  is_default INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS deal_stages (
  id TEXT PRIMARY KEY,
  pipeline_id TEXT NOT NULL REFERENCES pipelines(id),
  name TEXT NOT NULL,
  position INTEGER DEFAULT 0,
  probability REAL DEFAULT 0,
  rotting_days INTEGER DEFAULT 30,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS contacts (
  id TEXT PRIMARY KEY,
  company_id TEXT,
  first_name TEXT NOT NULL,
  last_name TEXT,
  email TEXT,
  phone TEXT,
  title TEXT,
  source TEXT DEFAULT 'manual',
  lead_score INTEGER DEFAULT 0,
  lead_status TEXT DEFAULT 'new',
  tags TEXT DEFAULT '[]',
  custom_fields TEXT DEFAULT '{}',
  address TEXT,
  city TEXT,
  state TEXT,
  zip TEXT,
  country TEXT DEFAULT 'US',
  notes TEXT,
  last_contacted_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS companies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT,
  industry TEXT,
  size TEXT,
  revenue TEXT,
  phone TEXT,
  address TEXT,
  city TEXT,
  state TEXT,
  zip TEXT,
  country TEXT DEFAULT 'US',
  tags TEXT DEFAULT '[]',
  custom_fields TEXT DEFAULT '{}',
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS deals (
  id TEXT PRIMARY KEY,
  pipeline_id TEXT NOT NULL REFERENCES pipelines(id),
  stage_id TEXT NOT NULL REFERENCES deal_stages(id),
  contact_id TEXT REFERENCES contacts(id),
  company_id TEXT REFERENCES companies(id),
  title TEXT NOT NULL,
  value REAL DEFAULT 0,
  currency TEXT DEFAULT 'USD',
  probability REAL DEFAULT 0,
  expected_close_date TEXT,
  actual_close_date TEXT,
  status TEXT DEFAULT 'open',
  lost_reason TEXT,
  won_reason TEXT,
  owner TEXT,
  tags TEXT DEFAULT '[]',
  custom_fields TEXT DEFAULT '{}',
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS activities (
  id TEXT PRIMARY KEY,
  contact_id TEXT REFERENCES contacts(id),
  company_id TEXT REFERENCES companies(id),
  deal_id TEXT REFERENCES deals(id),
  type TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT,
  due_date TEXT,
  completed_at TEXT,
  duration_minutes INTEGER,
  is_done INTEGER DEFAULT 0,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  contact_id TEXT REFERENCES contacts(id),
  company_id TEXT REFERENCES companies(id),
  deal_id TEXT REFERENCES deals(id),
  body TEXT NOT NULL,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tags (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  color TEXT DEFAULT '#6366f1',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS email_events (
  id TEXT PRIMARY KEY,
  contact_id TEXT REFERENCES contacts(id),
  deal_id TEXT,
  type TEXT NOT NULL,
  subject TEXT,
  opened_at TEXT,
  clicked_at TEXT,
  bounced INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS lead_scoring_rules (
  id TEXT PRIMARY KEY,
  field TEXT NOT NULL,
  operator TEXT NOT NULL,
  value TEXT NOT NULL,
  score INTEGER NOT NULL,
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS imports (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  file_name TEXT,
  total_rows INTEGER DEFAULT 0,
  imported INTEGER DEFAULT 0,
  skipped INTEGER DEFAULT 0,
  errors INTEGER DEFAULT 0,
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_contacts_company ON contacts(company_id);
CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email);
CREATE INDEX IF NOT EXISTS idx_contacts_lead_status ON contacts(lead_status);
CREATE INDEX IF NOT EXISTS idx_contacts_lead_score ON contacts(lead_score DESC);
CREATE INDEX IF NOT EXISTS idx_contacts_source ON contacts(source);
CREATE INDEX IF NOT EXISTS idx_companies_domain ON companies(domain);
CREATE INDEX IF NOT EXISTS idx_companies_industry ON companies(industry);
CREATE INDEX IF NOT EXISTS idx_deals_pipeline ON deals(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_deals_stage ON deals(stage_id);
CREATE INDEX IF NOT EXISTS idx_deals_contact ON deals(contact_id);
CREATE INDEX IF NOT EXISTS idx_deals_company ON deals(company_id);
CREATE INDEX IF NOT EXISTS idx_deals_status ON deals(status);
CREATE INDEX IF NOT EXISTS idx_deals_value ON deals(value DESC);
CREATE INDEX IF NOT EXISTS idx_activities_contact ON activities(contact_id);
CREATE INDEX IF NOT EXISTS idx_activities_deal ON activities(deal_id);
CREATE INDEX IF NOT EXISTS idx_activities_type ON activities(type);
CREATE INDEX IF NOT EXISTS idx_activities_due ON activities(due_date);
CREATE INDEX IF NOT EXISTS idx_notes_contact ON notes(contact_id);
CREATE INDEX IF NOT EXISTS idx_notes_deal ON notes(deal_id);
CREATE INDEX IF NOT EXISTS idx_email_events_contact ON email_events(contact_id);
CREATE INDEX IF NOT EXISTS idx_stages_pipeline ON deal_stages(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_stages_position ON deal_stages(position);
CREATE INDEX IF NOT EXISTS idx_activity_log_entity ON activity_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_activity_log_time ON activity_log(created_at DESC);
