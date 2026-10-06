## CWE Top 25 (2024) coverage
The table lists each 2024 CWE Top 25 weakness, whether this assessment found an instance, and the findings that carry it.
| Rank | CWE | Name | Found | Findings |
|---|---|---|---|---|
| 1 | CWE-79 | Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) | Yes | PB1-10 |
| 2 | CWE-787 | Out-of-bounds Write | No | — |
| 3 | CWE-89 | SQL Injection | Yes | APP-01, APP-02, PB2-05, PB2-06 |
| 4 | CWE-352 | Cross-Site Request Forgery | No | — |
| 5 | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) | Yes | CF-18, PB1-02 |
| 6 | CWE-125 | Out-of-bounds Read | No | — |
| 7 | CWE-78 | OS Command Injection | Yes | CI-01, PB2-01, PB2-02, PB2-03, PB2-04, PB2-15 |
| 8 | CWE-416 | Use After Free | No | — |
| 9 | CWE-862 | Missing Authorization | Yes | CF-09, PB1-03, PB2-10 |
| 10 | CWE-434 | Unrestricted Upload of File with Dangerous Type | No | — |
| 11 | CWE-94 | Improper Control of Generation of Code (Code Injection) | Yes | CI-01, CI-02 |
| 12 | CWE-20 | Improper Input Validation | Yes | APP-05, APP-10, APP-13, CF-01, CF-02, CF-06, CF-07, CF-08, CF-14, CF-15, CF-16, CF-18, PB1-07, PB1-11, PB1-12, PB1-15 |
| 13 | CWE-77 | Improper Neutralization of Special Elements used in a Command (Command Injection) | Yes | DET-02, DET-05, PB1-02 |
| 14 | CWE-287 | Improper Authentication | No | — |
| 15 | CWE-269 | Improper Privilege Management | No | — |
| 16 | CWE-502 | Deserialization of Untrusted Data | Yes | DET-16 |
| 17 | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | Yes | CF-11, CF-12, PB1-16, PB2-13, SEC-03, SEC-05, SEC-10 |
| 18 | CWE-863 | Incorrect Authorization | No | — |
| 19 | CWE-918 | Server-Side Request Forgery (SSRF) | No | — |
| 20 | CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | No | — |
| 21 | CWE-476 | NULL Pointer Dereference | Yes | CF-15 |
| 22 | CWE-798 | Use of Hard-coded Credentials | Yes | CI-14, PB1-06 |
| 23 | CWE-190 | Integer Overflow or Wraparound | No | — |
| 24 | CWE-400 | Uncontrolled Resource Consumption | Yes | CF-04, CF-05, CF-07, CI-05, CI-15, PB1-15 |
| 25 | CWE-306 | Missing Authentication for Critical Function | Yes | PB1-03 |

## All CWE identifiers cited (including those outside the Top 25)
| CWE | Name | Top 25 rank | Findings |
|---|---|---|---|
| CWE-79 | Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) | 1 | PB1-10 |
| CWE-89 | SQL Injection | 3 | APP-01, APP-02, PB2-05, PB2-06 |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) | 5 | CF-18, PB1-02 |
| CWE-78 | OS Command Injection | 7 | CI-01, PB2-01, PB2-02, PB2-03, PB2-04, PB2-15 |
| CWE-862 | Missing Authorization | 9 | CF-09, PB1-03, PB2-10 |
| CWE-94 | Improper Control of Generation of Code (Code Injection) | 11 | CI-01, CI-02 |
| CWE-20 | Improper Input Validation | 12 | APP-05, APP-10, APP-13, CF-01, CF-02, CF-06, CF-07, CF-08, CF-14, CF-15, CF-16, CF-18, PB1-07, PB1-11, PB1-12, PB1-15 |
| CWE-77 | Improper Neutralization of Special Elements used in a Command (Command Injection) | 13 | DET-02, DET-05, PB1-02 |
| CWE-502 | Deserialization of Untrusted Data | 16 | DET-16 |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | 17 | CF-11, CF-12, PB1-16, PB2-13, SEC-03, SEC-05, SEC-10 |
| CWE-476 | NULL Pointer Dereference | 21 | CF-15 |
| CWE-798 | Use of Hard-coded Credentials | 22 | CI-14, PB1-06 |
| CWE-400 | Uncontrolled Resource Consumption | 24 | CF-04, CF-05, CF-07, CI-05, CI-15, PB1-15 |
| CWE-306 | Missing Authentication for Critical Function | 25 | PB1-03 |
| CWE-1053 |  | — | DET-14, DET-19 |
| CWE-1059 | Insufficient Technical Documentation | — | SEC-08 |
| CWE-1078 |  | — | DET-08, DET-09, DET-18 |
| CWE-1104 | Use of Unmaintained Third Party Components | — | APP-06, DEP-01, DEP-02, DEP-03, DEP-04, DEP-06, DEP-07, DEP-08, DEP-09, DEP-10, DEP-12, DET-16, PB2-17 |
| CWE-1127 |  | — | APP-14 |
| CWE-116 | Improper Encoding or Escaping of Output | — | CI-10, DET-02, DET-05, DET-12, PB1-10, PB2-14 |
| CWE-117 |  | — | CI-10 |
| CWE-1188 | Initialization of a Resource with an Insecure Default | — | APP-04, APP-09, APP-12, DET-07, PB2-13 |
| CWE-1236 | Improper Neutralization of Formula Elements in a CSV File | — | APP-07 |
| CWE-1286 | Improper Validation of Syntactic Correctness of Input | — | APP-13 |
| CWE-1333 | Inefficient Regular Expression Complexity (ReDoS) | — | CF-05, CF-07, PB1-15 |
| CWE-1357 | Reliance on Insufficiently Trustworthy Component | — | DEP-05, DEP-07, DEP-09 |
| CWE-1395 | Dependency on Vulnerable Third-Party Component | — | DEP-01, DEP-02, DEP-04, DEP-08, DEP-12 |
| CWE-172 |  | — | CF-16 |
| CWE-176 |  | — | APP-10 |
| CWE-178 | Improper Handling of Case Sensitivity | — | DET-06 |
| CWE-183 |  | — | APP-04, PB2-12 |
| CWE-184 | Incomplete List of Disallowed Inputs | — | DET-06 |
| CWE-248 |  | — | CF-14, PB1-12, PB1-13 |
| CWE-250 | Execution with Unnecessary Privileges | — | CI-13 |
| CWE-259 | Use of Hard-coded Password | — | PB1-06 |
| CWE-272 |  | — | CI-13 |
| CWE-284 | Improper Access Control | — | APP-08, CF-10, PB1-03 |
| CWE-285 | Improper Authorization | — | PB2-09, PB2-12 |
| CWE-295 | Improper Certificate Validation | — | CF-03, PB2-11 |
| CWE-312 | Cleartext Storage of Sensitive Information | — | CI-03, PB2-08, SEC-03, SEC-04 |
| CWE-319 | Cleartext Transmission of Sensitive Information | — | DET-13 |
| CWE-330 |  | — | PB2-07 |
| CWE-338 |  | — | PB2-07 |
| CWE-345 | Insufficient Verification of Data Authenticity | — | DET-03, DET-04 |
| CWE-349 | Acceptance of Extraneous Untrusted Data With Trusted Data | — | DET-03, DET-04 |
| CWE-357 |  | — | PB1-18 |
| CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | — | SEC-05 |
| CWE-390 | Detection of Error Condition Without Action | — | CI-09, PB1-09 |
| CWE-391 | Unchecked Error Condition | — | PB2-16 |
| CWE-396 |  | — | CI-09, PB2-16 |
| CWE-409 | Improper Handling of Highly Compressed Data (Data Amplification) | — | CF-04 |
| CWE-426 |  | — | CI-08 |
| CWE-427 |  | — | CI-08, DEP-10 |
| CWE-459 |  | — | CF-04 |
| CWE-471 |  | — | PB1-14 |
| CWE-477 | Use of Obsolete Function | — | CF-17 |
| CWE-478 |  | — | PB1-08 |
| CWE-494 | Download of Code Without Integrity Check | — | DEP-01, DEP-02, DEP-03, DEP-05, DEP-10, DET-16, SEC-10 |
| CWE-521 | Weak Password Requirements | — | PB1-06 |
| CWE-522 |  | — | DEP-02 |
| CWE-532 | Insertion of Sensitive Information into Log File | — | CF-12, CI-03, PB1-16, PB2-08 |
| CWE-540 | Inclusion of Sensitive Information in Source Code | — | SEC-03, SEC-04, SEC-05, SEC-09, SEC-10 |
| CWE-561 | Dead Code | — | PB1-17 |
| CWE-573 |  | — | PB1-14 |
| CWE-611 |  | — | CI-05 |
| CWE-617 |  | — | CF-13 |
| CWE-625 |  | — | CF-06, CF-08 |
| CWE-628 |  | — | DET-08 |
| CWE-636 | Not Failing Securely (Failing Open) | — | PB1-08 |
| CWE-639 | Authorization Bypass Through User-Controlled Key (IDOR) | — | CF-09, CF-10 |
| CWE-640 |  | — | PB2-09 |
| CWE-665 |  | — | APP-05, DET-07 |
| CWE-670 |  | — | APP-03, PB1-09, PB1-13, PB1-17 |
| CWE-672 |  | — | APP-06 |
| CWE-674 |  | — | CI-15 |
| CWE-682 |  | — | PB1-09, PB1-13 |
| CWE-692 |  | — | CF-06 |
| CWE-693 | Protection Mechanism Failure | — | DET-03, DET-04, DET-06, DET-07, SEC-08 |
| CWE-697 | Incorrect Comparison | — | PB1-08 |
| CWE-703 |  | — | CF-13, CF-16 |
| CWE-73 |  | — | PB2-04, PB2-15 |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | — | APP-08 |
| CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection) | — | CF-01, DET-02, DET-05, PB1-01, PB1-04, PB1-05, PB1-07 |
| CWE-754 | Improper Check for Unusual or Exceptional Conditions | — | CF-15, PB1-12 |
| CWE-776 |  | — | CI-05 |
| CWE-807 |  | — | DET-04, PB1-11 |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | — | CI-02, DEP-02, DEP-03, DEP-05, DEP-06 |
| CWE-840 |  | — | PB1-18 |
| CWE-841 |  | — | PB2-10 |
| CWE-88 | Improper Neutralization of Argument Delimiters in a Command (Argument Injection) | — | CF-01, PB1-02, PB1-05, PB2-03 |
| CWE-90 | Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection) | — | PB1-04 |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment) | — | CF-02 |
| CWE-93 |  | — | PB2-14 |
| CWE-943 | Improper Neutralization of Special Elements in Data Query Logic | — | APP-01, APP-02, APP-12, PB1-01, PB1-05, PB1-07, PB2-05, PB2-06 |
