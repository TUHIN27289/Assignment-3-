# Security Requirements

| Requirement ID | Requirement/User Story Description | Priority | Complexity |
|---|---|---|---|
| SR-01 | **MFA (TOTP) for all AEC staff and delegate accounts.** As an AEC staff member or state Commissioner's delegate, I must enter a time-based one-time password (TOTP, RFC 6238) in addition to my password before a session is issued, so that a phished or stolen password alone cannot give an attacker access to enrolment, candidate or result functions. | High | Medium |
| SR-02 | **Role-based access control with least privilege, enforced server side.** As the platform owner, I need every request authorised on the server against the caller's role, with deny by default, so that a user can perform only the actions their role requires and hiding buttons in the UI or altering client requests cannot bypass permissions. | High | Medium |
