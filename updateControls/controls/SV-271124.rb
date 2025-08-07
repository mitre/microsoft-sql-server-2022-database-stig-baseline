control 'SV-271124' do
  title 'SQL Server must allow only the information system security manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', "Obtain the list of approved audit maintainers from the system documentation.

Use the following query to review database roles and their membership, all of which enable the ability to create and maintain audit specifications.

SELECT
    R.name AS role_name,
    RM.name AS role_member_name,
    RM.type_desc
FROM sys.database_principals R
JOIN sys.database_role_members DRM ON 
    R.principal_id = DRM.role_principal_id
JOIN sys.database_principals RM ON 
    DRM.member_principal_id = RM.principal_id
WHERE R.type = 'R'
    AND R.name = 'db_owner'
ORDER BY 
    role_member_name

If any role memberships are not documented and authorized, this is a finding.	


Review the database roles and individual users that have the following permissions, all of which enable the ability to create and maintain audit definitions.

ALTER ANY DATABASE AUDIT
CONTROL

Use the following query to determine the roles and users that have the listed permissions:

SELECT
	PERM.permission_name,
	DP.name AS principal_name,
	DP.type_desc AS principal_type,
	DBRM.role_member_name
FROM sys.database_permissions PERM
JOIN sys.database_principals DP ON PERM.grantee_principal_id = DP.principal_id
LEFT OUTER JOIN (
	SELECT
		R.principal_id AS role_principal_id,
		R.name AS role_name,
		RM.name AS role_member_name
	FROM sys.database_principals R
	JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
	JOIN sys.database_principals RM ON DRM.member_principal_id = RM.principal_id
	WHERE R.type = 'R'
) DBRM ON DP.principal_id = DBRM.role_principal_id
WHERE PERM.permission_name IN ('CONTROL','ALTER ANY DATABASE AUDIT')
ORDER BY
	permission_name, 
	principal_name, 
	role_member_name


If any of the roles or users returned have permissions that are not documented, or the documented audit maintainers do not have permissions, this is a finding."
  desc 'fix', 'Create a database role specifically for audit maintainers, and give it permission to maintain audits without granting it unnecessary permissions. (The role name used below is an example; other names may be used.)

CREATE ROLE DATABASE_AUDIT_MAINTAINERS;
GO

GRANT ALTER ANY DATABASE AUDIT TO DATABASE_AUDIT_MAINTAINERS;
GO

Use REVOKE and/or DENY and/or ALTER ROLE ... DROP MEMBER ... statements to remove the ALTER ANY DATABASE AUDIT permission from all users. Then, for each authorized database user, run the statement:

ALTER ROLE DATABASE_AUDIT_MAINTAINERS ADD MEMBER;
GO

Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ... statements to remove CONTROL DATABASE permission from logins that do not need it.'
  impact 0.5
  tag check_id: 'C-75167r1107986_chk'
  tag severity: 'medium'
  tag gid: 'V-271124'
  tag rid: 'SV-271124r1109215_rule'
  tag stig_id: 'SQLD-22-000700'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-75074r1109214_fix'
  tag 'documentable'
  tag legacy: ['SV-81851', 'V-67361', 'SV-93779', 'V-79073']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

  if input('server_audit_at_database_level_required')
    impact 0.5
  else
    impact 0.0
    desc 'Inspec attributes has specified that SQL Server Audit is not in use at
    the database level, this is not applicable (NA)'
  end

  approved_audit_maintainers = input('approved_audit_maintainers')

  # The query in check-text is assumes the presence of STIG schema as supplied with
  # the STIG supplemental. The below query ( partially taken from 2016 MSSQL STIG)
  # will work without STIG supplemental schema.

  query = %{
    SELECT DPE.PERMISSION_NAME AS 'PERMISSION',
           DPM.NAME            AS 'ROLE MEMBER',
           DPR.NAME            AS 'ROLE NAME'
    FROM   SYS.DATABASE_ROLE_MEMBERS DRM
           JOIN SYS.DATABASE_PERMISSIONS DPE
             ON DRM.ROLE_PRINCIPAL_ID = DPE.GRANTEE_PRINCIPAL_ID
           JOIN SYS.DATABASE_PRINCIPALS DPR
             ON DRM.ROLE_PRINCIPAL_ID = DPR.PRINCIPAL_ID
           JOIN SYS.DATABASE_PRINCIPALS DPM
             ON DRM.MEMBER_PRINCIPAL_ID = DPM.PRINCIPAL_ID
    WHERE  DPE.PERMISSION_NAME IN ( 'CONTROL', 'ALTER ANY DATABASE AUDIT' )
    OR DPM.NAME IN ('db_owner')
  }

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  describe 'List of approved audit maintainers' do
    subject { sql_session.query(query).column('role member').uniq }
    it { should match_array approved_audit_maintainers }
  end
end
