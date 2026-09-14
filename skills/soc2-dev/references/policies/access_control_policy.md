# Access Control Policy

## Purpose

The goal is to restrict access to information, systems, networks, and facilities to authorized individuals, aligning with business goals.

## Scope

This policy applies to all [COMPANY NAME] information systems processing, storing, or transmitting confidential data as defined in the [COMPANY NAME] Data Management Policy. It is relevant to all [COMPANY NAME] employees and external parties with access to [COMPANY NAME] networks and resources.

## Policy

Access to computing resources is restricted to those with a legitimate business need. Access rights are allocated or revoked according to this Access Control Policy.

## Access Control Requirements

[COMPANY NAME] will determine the type and level of access for individual users based on the "principle of least privilege" ensuring access is granted only as necessary to perform job functions. Any permissions not explicitly granted are prohibited by default. Role-Based Access Control (RBAC) will be the primary method for consistent access control, assigning rights and restrictions to groups. Additional permissions may be granted to individual user accounts with system owner approval. Multi-Factor Authentication (MFA) is required for all privileged access to production infrastructure.

## Network Access

- Access to [COMPANY NAME] networks must be formally documented, including the standard role, approver, grantor, and date.
- Access is granted only to authorized employees/contractors and third-parties with a business need and signed contracts or statements of work.

- Guests may access guest networks after registering with office staff.
- Remote connections to production systems must be encrypted.

## Customer Access Management

For cross-account access using AWS IAM roles, generate external IDs to ensure unique and secure configurations, preventing impersonation. External IDs must be unique across all customers to avoid security risks.

## User Access Management

All personnel must have unique user identifiers, and credentials must not be shared. Separate accounts should be used for normal and administrative functions where feasible. Shared administrative accounts may use password management systems for business continuity.

### User Registration and Deregistration

Only authorized administrators can create new user IDs based on documented requests and approvals. User IDs must be promptly disabled or removed when no longer needed, following SLAs.

### User Access Provisioning

- New employees or contractors must complete all HR on-boarding tasks before accessing production systems.
- Access is restricted to job necessities and documented with appropriate approvals.

- Access is not granted before the official start date.
- Records of permission changes must be maintained for at least one year.

### Management of Privileged Access

Granting of administrative rights requires asset owner approval and is strictly controlled.

### User Access Reviews

Semi annual reviews of user access rights are conducted to ensure compliance. Access reviews also occur with any job role change.

### Removal & Adjustment of Access Rights

Access rights are removed upon termination or job function change within 40 business hours.

### Access Provisioning, Deprovisioning, and Change Procedure

Details on access management procedures are available in Appendix A of this policy.

### Segregation of Duties

Conflicting duties are separated to prevent unauthorized use or modification of assets. No single person should have access without authorization or detection. Collusion potential is considered in access level determinations.

## User Responsibility for Secret Authentication Information

All personnel and third-party users must protect their secret authentication information according to the Information Security Policy.

## Password Policy

- Passwords for confidential systems should have at least 10 characters, including one uppercase letter and one number.
- Systems should prevent the reuse of the last 16 passwords.

- Accounts lock after 6 failed attempts.
- Passwords expire every 90 days.

- Initial passwords must be unique and changed upon first login.
- User identity verification is required for manual password resets.

- No limit on character types for passwords.
- Maximum password length is 64 characters.

- Do not use secret questions for password resets.
- Email verification is required for password changes.

- Current password must be entered during changes.
- New passwords checked against common and leaked passwords.

- Regular checks for password compromise.
- Passwords stored using hashed and salted formats.

- Enforce account lockout and brute-force protection.

## System and Application Access

Applications must restrict access to authorized users based on business needs, data sensitivity, and risk assessments. Default accounts and vendor credentials must be changed before deployment.

### Secure Log-on Procedures

Log-on controls should match data sensitivity and access risk, supported by overall security architecture.

### Password Management System

Interactive systems help enforce password standards and protect password storage and transmission through cryptographic methods.

### Use of Privileged Utility Programs

Restrict the use of programs that can override controls to essential personnel. System changes and utility use must be logged, and extraneous programs removed.

### Access to Program Source Code

Strict control of source code access is required to prevent unauthorized changes and protect intellectual property. Access must be logged for review.

## Exceptions

Requests for exceptions to this policy must be approved by the IT Manager.

## Violations & Enforcement

Report policy violations to the IT Manager. Violations may lead to system privilege withdrawal, disciplinary action, or employment termination.
