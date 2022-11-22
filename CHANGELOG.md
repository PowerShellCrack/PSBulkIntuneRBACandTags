# IntuneRolesCreation.ps1

## 1.4.3 - February 03, 2022

- Fixed Tag filter for scope assignment; check filter to ensure assigns appropriate tag
- Fixed GenerateScopeGroup.ps1 script output; change output to be Export-CSV instead of Out-file with no quotes
- Parameterized GenerateScopeGroup.ps1 list input and output; added example

## 1.4.2 - February 02, 2022

- Added NoPrompt parameter to creation script; creates member groups without prompting.
- Moved all sample code to external file; cleaned up main script
- Added comments to script; explain process more clearly
- Add Rule Expression check for Azure AD groups; updates rule if different from data set

## 1.4.1 - February 01, 2022

- Added device filter to both Tag and roles instead of just Azure AD
- Added Invoke Assignments output; change Null output to id value; for verbose logging
- Changed 'Done' output to display more detail; Outputs Tag ID and GUID_ID for Assignments
- Added Azure AD group id collection and output; no supports multiple groups assignment at one time.
- Added authtoken check on every loop; mitigates token expiration during script run
- Wrote README.md to explain usage
- Reordered wording for assignment output; reduced and clarified output
- Changed Assignment name for Roles to reflect device types; allows granular control and organization upon devices

## 1.3.0 - January 28, 2022

- Added export in csv for errors. Provides a easier means to troubleshoot
- Added stopwatch timer to track script progress and time lapse; displays runtime at end of script
- Added summary output to show status changes
- Change tag iteration to grouping; support multiple groups assignment per tag/role
- Added Azure AD check for DefaultAdminAadGroup; prompts to create if needed

## 1.2.0 - January 27, 2022

- Fixed output for names with unsupported characters
- Added check for rule length; skips object in loop
- Added token check after Ad group and roles check; makes token refresh if expired before assignments
- Change correlation of CSV files to use key columns (Region and Area); produce more accurate assignments

## 1.1.0 - January 26, 2022

- Wrote API call for dynamic group creations
- Wrote get API calls for Tag, role and Groups; provides check and balances
- Included SkipRoleTags parameter; disable un-needed tagging for Roles
- Included SkipRoleAssignment parameter; does not assign Roles to Ad groups (good for testing)
- Added device filter to Azure Ad groups
- Developed deletion script to assist with testing

## 1.0.1 - January 25, 2022

- Wrote get API call for MSgraph token, and put API calls for Intune Role and Intune Tagging
- Added csv import with loops process; added correlation between csv files

## 1.0.0 - January 24, 2022

- Initial
