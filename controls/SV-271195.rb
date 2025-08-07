control 'SV-271195' do
  title 'SQL Server must enforce access restrictions associated with changes to the configuration of the database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Execute the following query to obtain a listing of user databases whose owner is a member of a fixed server role:

 SELECT 
              D.name AS database_name, SUSER_SNAME(D.owner_sid) AS owner_name,
              FRM.is_fixed_role_member
FROM sys.databases D
OUTER APPLY (
              SELECT MAX(fixed_role_member) AS is_fixed_role_member
              FROM (
                            SELECT IS_SRVROLEMEMBER(R.name, SUSER_SNAME(D.owner_sid)) AS fixed_role_member
                            FROM sys.server_principals R
                            WHERE is_fixed_role = 1
              ) A
) FRM
WHERE D.database_id > 4
              AND (FRM.is_fixed_role_member = 1 
                            OR FRM.is_fixed_role_member IS NULL)
ORDER BY database_name 

If no databases are returned, this is not a finding. 

For each database/login returned, review the Server Role memberships:
1. In SQL Server Management Studio, expand "Logins".
2. Double-click the name of the login.
3. Click the "Server Roles" tab.

If any server roles are selected, but not documented and authorized, this is a finding.'
  desc 'fix', 'Remove unauthorized users from roles:

ALTER ROLE DROP MEMBER user;

https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?

Set the owner of the database to an authorized login:

ALTER AUTHORIZATION ON database::DatabaseName TO login;

https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?'
  impact 0.5
  tag check_id: 'C-75238r1108893_chk'
  tag severity: 'medium'
  tag gid: 'V-271195'
  tag rid: 'SV-271195r1109208_rule'
  tag stig_id: 'SQLD-22-003100'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-75145r1109207_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
