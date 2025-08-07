control 'SV-271170' do
  title 'The Database Master Key must be encrypted by the Service Master Key, where a Database Master Key is required and another encryption method has not been specified.'
  desc 'When not encrypted by the Service Master Key, system administrators or application administrators may access and use the Database Master Key to view sensitive data that they are not authorized to view. Where alternate encryption means are not feasible, encryption by the Service Master Key may be necessary. To help protect sensitive data from unauthorized access by DBAs, mitigations may be required. Mitigations may include automatic alerts or other audit events when the Database Master Key is accessed outside of the application or by a DBA account.'
  desc 'check', 'If no databases require encryption, this is not a finding. 

From the query prompt: 

SELECT name 
FROM [master].sys.databases 
WHERE is_master_key_encrypted_by_server = 1 
AND state = 0; 

If no databases are returned by the query, this is not a finding. 

For any databases returned, verify in the System Security Plan that encryption of the Database Master Key using the Service Master Key is acceptable and approved by the Information Owner, and the encrypted data does not require additional protections to deter or detect DBA access. If not approved, this is a finding. 

If approved and additional protections are required, verify the additional requirements are in place in accordance with the System Security Plan. These may include additional auditing on access of the Database Master Key with alerts or other automated monitoring. 

If the additional requirements are not in place, this is a finding.'
  desc 'fix', 'Where possible, encrypt the Database Master Key with a password known only to the application administrator.  Where not possible, configure additional audit events or alerts to detect unauthorized access to the Database Master Key by users not authorized to view sensitive data.'
  impact 0.5
  tag check_id: 'C-75213r1109189_chk'
  tag severity: 'medium'
  tag gid: 'V-271170'
  tag rid: 'SV-271170r1109190_rule'
  tag stig_id: 'SQLD-22-001700'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-75120r1108125_fix'
  tag 'documentable'
  tag legacy: ['SV-81871', 'V-67381', 'SV-93793', 'V-79087']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']

  query = %(
    SELECT NAME
    FROM   [master].sys.databases
    WHERE  is_master_key_encrypted_by_server = 1
           AND owner_sid <> 1
           AND state = 0
           AND name = '#{input('db_name')}';
  )

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  results = sql_session.query(query)

  if results.empty?
    impact 0.0
    desc 'No databases require encryption hence this is not a finding'
  end

  describe 'The following checks must be performed manually' do
    skip "The following checks must be performed manually:
    For the database #{results.column('name')} verify in the System Security
    Plan that encryption of the Database Master Key using the Service Master Key
    is acceptable and approved by the Information Owner, and the encrypted data
    does not require additional protections to deter or detect DBA access.
    If not approved, this is a finding.

    If approved and additional protections are required, then verify the additional
    requirements are in place in accordance with the System Security Plan. These
    may include additional auditing on access of the Database Master Key with
    alerts or other automated monitoring.

    If the additional requirements are not in place, this is a finding."
  end
end
