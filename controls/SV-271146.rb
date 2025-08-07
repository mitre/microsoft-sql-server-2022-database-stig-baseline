control 'SV-271146' do
  title 'Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be owned by database/DBMS principals authorized for ownership.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who uses the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects in SQL Server rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', 'Review system documentation to identify SQL Server accounts authorized to own database objects. 

If the SQL Server database ownership list does not exist or needs to be updated, this is a finding. 

Use the following query to make this determination: 

;with objects_cte as
(SELECT o.name, o.type_desc,
   CASE
    WHEN o.principal_id is null then s.principal_id
     ELSE o.principal_id
    END as principal_id
 FROM sys.objects o
 INNER JOIN sys.schemas s
 ON o.schema_id = s.schema_id
 WHERE o.is_ms_shipped = 0
)
SELECT cte.name, cte.type_desc, dp.name as ObjectOwner 
FROM objects_cte cte
INNER JOIN sys.database_principals dp
ON cte.principal_id = dp.principal_id
ORDER BY dp.name, cte.name

If any of the listed owners are not authorized, this is a finding.'
  desc 'fix', 'Document and obtain approval for any account(s) authorized for object ownership. If necessary, use the ALTER AUTHORIZATION command to change object ownership to an authorized account. 

Example provided below. 

ALTER AUTHORIZATION ON OBJECT::test.table TO AuthorizedUser;

https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql'
  impact 0.5
  tag check_id: 'C-75189r1109181_chk'
  tag severity: 'medium'
  tag gid: 'V-271146'
  tag rid: 'SV-271146r1109183_rule'
  tag stig_id: 'SQLD-22-001300'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-75096r1109182_fix'
  tag 'documentable'
  tag legacy: ['SV-81861', 'V-67371', 'SV-93785', 'V-79079']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  # The query in check text is assumes the presence of STIG schema as supplied
  # with the STIG supplemental. The below query ( taken from 2016 MSSQL STIG)
  # will work without STIG supplemental schema.

  query = %{
      ;WITH OBJECTS_CTE
           AS (SELECT O.NAME,
                      O.TYPE_DESC,
                      CASE
                        WHEN O.PRINCIPAL_ID IS NULL THEN S.PRINCIPAL_ID
                        ELSE O.PRINCIPAL_ID
                      END AS PRINCIPAL_ID
               FROM   SYS.OBJECTS O
                      INNER JOIN SYS.SCHEMAS S
                              ON O.SCHEMA_ID = S.SCHEMA_ID
               WHERE  O.IS_MS_SHIPPED = 0)
      SELECT CTE.NAME,
             CTE.TYPE_DESC,
             DP.NAME AS OBJECTOWNER
      FROM   OBJECTS_CTE CTE
             INNER JOIN SYS.DATABASE_PRINCIPALS DP
                     ON CTE.PRINCIPAL_ID = DP.PRINCIPAL_ID
      ORDER  BY DP.NAME,
                CTE.NAME
  }

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  describe "Authorized users for Database: #{input('db_name')}" do
    subject { sql_session.query(query).column('objectowner').uniq }
    it { should cmp input('authorized_principals') }
  end
end
