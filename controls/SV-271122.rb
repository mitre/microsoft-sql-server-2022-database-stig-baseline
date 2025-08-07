control 'SV-271122' do
  title 'SQL Server must protect against a user falsely repudiating by ensuring databases are not in a trust relationship.'
  desc "Nonrepudiation of actions taken is required to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Nonrepudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account.

SQL Server provides the ability for high privileged accounts to impersonate users in a database using the TRUSTWORTHY feature. This will allow members of the fixed database role to impersonate any user within the database."
  desc 'check', "If the database being reviewed is MSDB, trustworthy is required to be enabled, and therefore this is not a finding.

Execute the following query:

SELECT
[DatabaseName] = d.name
,[DatabaseOwner] = login.name
,[IsTrustworthy] = CASE
WHEN d.is_trustworthy_on = 0 THEN 'No'
WHEN d.is_trustworthy_on = 1 THEN 'Yes'
END
,[IsOwnerPrivilege] = CASE
WHEN role.name IN ('sysadmin','securityadmin')
OR permission.permission_name = 'CONTROL SERVER'
THEN 'YES'
ELSE 'No'
END
FROM sys.databases d
LEFT JOIN sys.server_principals login ON d.owner_sid = login.sid
LEFT JOIN sys.server_role_members rm ON login.principal_id = rm.member_principal_id
LEFT JOIN sys.server_principals role ON rm.role_principal_id = role.principal_id
LEFT JOIN sys.server_permissions permission ON login.principal_id = permission.grantee_principal_id
WHERE d.name <> 'msdb'

If trustworthy is not enabled, this is not a finding.

If trustworthy is enabled and the database owner is not a privileged account, this is not a finding.

If trustworthy is enabled and the database owner is a privileged account, review the system documentation to determine if the trustworthy property is required and authorized. If this is not documented, this is a finding."
  desc 'fix', 'Disable trustworthy on the database.

ALTER DATABASE [<database name>] SET TRUSTWORTHY OFF;'
  impact 0.5
  tag check_id: 'C-75165r1109178_chk'
  tag severity: 'medium'
  tag gid: 'V-271122'
  tag rid: 'SV-271122r1109180_rule'
  tag stig_id: 'SQLD-22-000600'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-75072r1109179_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
