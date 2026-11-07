-- SQL script to create reports database for PostgreSQL
-- 
-- To run, type: psql template1 < reports-pgsql.sql
--
-- $Id: reports-pgsql.sql,v 1.4 2007/04/16 11:02:36 mr-russ Exp $

CREATE DATABASE phppgadmin;

\connect phppgadmin

CREATE TABLE ppa_reports (
	report_id SERIAL,
	report_name varchar(255) NOT NULL,
	db_name varchar(255) NOT NULL,
	date_created date DEFAULT NOW() NOT NULL,
	created_by varchar(255) NOT NULL,
	descr text,
	report_sql text NOT NULL,
	paginate boolean NOT NULL,
	PRIMARY KEY (report_id)
);

-- Everyone may read and add reports, but only the user who created a
-- report can change or delete it. Without this, any login could rewrite
-- someone else's report_sql, which that user then runs.
GRANT SELECT,INSERT,UPDATE,DELETE ON ppa_reports TO PUBLIC;
GRANT SELECT,UPDATE ON ppa_reports_report_id_seq TO PUBLIC;

ALTER TABLE ppa_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY ppa_reports_select ON ppa_reports FOR SELECT USING (true);
CREATE POLICY ppa_reports_insert ON ppa_reports FOR INSERT WITH CHECK (created_by = current_user);
CREATE POLICY ppa_reports_update ON ppa_reports FOR UPDATE
	USING (created_by = current_user) WITH CHECK (created_by = current_user);
CREATE POLICY ppa_reports_delete ON ppa_reports FOR DELETE USING (created_by = current_user);

-- Upgrading an existing install: connect to the reports database (usually
-- phppgadmin) as its owner and run the ALTER TABLE and the four CREATE POLICY
-- lines above. Row level security does not apply to the table's owner or to
-- superusers, so report editing is only restricted for ordinary logins.
