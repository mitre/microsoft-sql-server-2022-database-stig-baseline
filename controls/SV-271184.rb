control 'SV-271184' do
  title 'SQL Server must associate organization-defined types of security labels having organization-defined security label values with information in process, transit, or storage.'
  desc 'Without the association of security labels to information, there is no basis for SQL Server to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies; reflect special dissemination, handling, or distribution instructions; or support other aspects of the information security policy.

One example includes marking data as classified or CUI. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of SQL Server, a third-party product, or custom application code.

'
  desc 'check', 'If security labeling is not required, this is not a finding.

If security labeling requirements have been specified, but neither a third-party solution nor a SQL Server Row-Level security solution is implemented that reliably maintains labels on information, this is a finding.'
  desc 'fix', 'Deploy SQL Server Row-Level Security (refer to link below) or a third-party software, or add custom data structures, data elements, and application code, to provide reliable security labeling of information.

https://msdn.microsoft.com/en-us/library/dn765131.aspx'
  impact 0.5
  tag check_id: 'C-75227r1109201_chk'
  tag severity: 'medium'
  tag gid: 'V-271184'
  tag rid: 'SV-271184r1109203_rule'
  tag stig_id: 'SQLD-22-002600'
  tag gtitle: 'SRG-APP-000313-DB-000309'
  tag fix_id: 'F-75134r1109202_fix'
  tag satisfies: ['SRG-APP-000311-DB-000308', 'SRG-APP-000314-DB-000310']
  tag 'documentable'
  tag cci: ['CCI-002262', 'CCI-002263', 'CCI-002264']
  tag nist: ['AC-16 a', 'AC-16 a', 'AC-16 a']
end
