control 'SV-271147' do
  title 'The role(s)/group(s) used to modify database structure (including but not limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be restricted to authorized users.'
  desc 'If SQL Server were to allow any user to make changes to database structure or logic, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.

DBMS functionality and the nature and requirements of databases will vary; so, while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. The requirements for production servers will be more restrictive than those used for development and research.

The DBMS must enforce software installation by users based on what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree regarding being potentially malicious is unknown or suspect) by the organization. 

In the case of a database management system, this requirement covers stored procedures, functions, triggers, views, etc.'
  desc 'check', "If the SQL Server instance supports only software development, experimentation, and/or developer-level testing (i.e., excluding production systems, integration testing, stress testing, and user acceptance testing), this is not a finding. 

Obtain a listing of users and roles who are authorized to create, alter, or replace logic modules from the server documentation.

In each user database, execute the following query:

SELECT P.type_desc AS principal_type, P.name AS principal_name,
O.type_desc,
CASE class
WHEN 0 THEN DB_NAME()
WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
WHEN 3 THEN SCHEMA_NAME(major_id)
ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
END AS securable_name, DP.state_desc, DP.permission_name
FROM sys.database_permissions DP
JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)

SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
FROM sys.database_principals R
JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
WHERE R.name IN ('db_ddladmin','db_owner')
AND M.name <> 'dbo'

If any users or role permissions returned are not authorized to modify the specified object or type, this is a finding. 

If any user or role membership is not authorized, this is a finding."
  desc 'fix', 'Document and obtain approval for any nonadministrative users who require the ability to create, alter, or replace logic modules.

Revoke the ALTER permission from unauthorized users and roles:

REVOKE ALTER ON [<Object Name>] FROM [<Principal Name>]'
  impact 0.5
  tag check_id: 'C-75190r1109184_chk'
  tag severity: 'medium'
  tag gid: 'V-271147'
  tag rid: 'SV-271147r1111078_rule'
  tag stig_id: 'SQLD-22-001400'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-75097r1109185_fix'
  tag 'documentable'
  tag legacy: ['SV-93787', 'V-79081']
  tag cci: ['CCI-001499', 'CCI-003980']
  tag nist: ['CM-5 (6)', 'CM-11 (2)']
end
