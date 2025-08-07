control 'SV-271169' do
  title 'The Database Master Key encryption password must meet DOD password complexity requirements.'
  desc 'Weak passwords may be easily guessed. When passwords are used to encrypt keys used for encryption of sensitive data, the confidentiality of all data encrypted using that key is at risk.

Current DOD passwords require the following: 
- minimum of 15 characters;
- at least one uppercase character;
- one lowercase character;
- one special character;
- one numeric character, and
- at least eight characters changed from the previous password.'
  desc 'check', "From the query prompt: 

SELECT name 
FROM [master].sys.databases 
WHERE state = 0 

Repeat for each database: 
From the query prompt: 

USE [database name] 
SELECT COUNT(name) 
FROM sys.symmetric_keys s, sys.key_encryptions k 
WHERE s.name = '##MS_DatabaseMasterKey##' 
AND s.symmetric_key_id = k.key_id 
AND k.crypt_type in ('ESKP', 'ESP2', 'ESP3')

If the value returned is zero, this is not applicable.

If the value returned is greater than zero, a Database Master Key exists and is encrypted with a password. 

Review procedures and evidence of password requirements used to encrypt Database Master Keys. 

If the passwords do not meet DOD password standards, this is a finding."
  desc 'fix', "Assign an encryption password to the Database Master Key that is a minimum of 15 characters with at least one uppercase character, one lowercase character, one special character, one numeric character, and at least eight characters changed from the previous password. To change the Database Master Key encryption password: 

USE [database name];
ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = 'new password'; 

Note: Do not change the Database Master Key encryption method until the effects are thoroughly reviewed. Changing the master key encryption causes all encryption using the Database Master Key to be decrypted and reencrypted. This action should not be taken during a high-demand time. 

Refer to the SQL Server documentation found here prior to reencrypting the Database Master Key: 
https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/create-a-database-master-key?"
  impact 0.5
  tag check_id: 'C-75212r1108121_chk'
  tag severity: 'medium'
  tag gid: 'V-271169'
  tag rid: 'SV-271169r1109188_rule'
  tag stig_id: 'SQLD-22-001600'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-75119r1109187_fix'
  tag 'documentable'
  tag legacy: ['SV-93791', 'V-79085']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']

  query = %{
    SELECT
          COUNT(credential_id) AS count_of_ids
    FROM
          [master].sys.master_key_passwords
  }

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  describe 'Count of `Database Master Key passwords` stored in credentials within the database' do
    subject { sql_session.query(query).row(0).column('count_of_ids') }
    its('value') { should cmp 0 }
  end  
end
