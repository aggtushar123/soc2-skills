# Secure Development Policy

## Purpose

To ensure that information security is designed and implemented within the development lifecycle for applications and information systems.

## Scope

This policy applies to all [COMPANY NAME] applications and information systems that are business critical and/or process, store, or transmit confidential data. It is applicable to all internal and external engineers and developers of [COMPANY NAME] software and infrastructure.

## Policy

This policy outlines the rules for the acquisition and development of software and systems within [COMPANY NAME].

## System Change Control Procedures

Changes to systems within the development lifecycle shall be controlled using formal change control procedures. These procedures and requirements are described in the [COMPANY NAME] Operations Security Policy. Significant code changes must be reviewed and approved by the VP of Engineering before being merged into any production branch in accordance with [COMPANY NAME]'s Secure Software Development Process. Change control procedures shall ensure that development, testing, and deployment of changes are not performed by a single individual without approval and oversight.

## Software Version Control

All [COMPANY NAME] software is version controlled and synced between contributors (developers). Access to the central repository is restricted based on an employee's role. All code is written, tested, and saved in a local repository before being synced to the origin repository.

## Technical Review of Applications after Operating Platform Changes

When operating platforms are changed, business-critical applications shall be reviewed and tested to ensure that there is no adverse impact on organizational operations or security.

## Restrictions on Changes to Software Packages

Modifications to third-party business application packages shall be discouraged, limited to necessary changes, and all changes shall be strictly controlled.

## Secure System Engineering Principles

Principles for engineering secure systems shall be established, documented, maintained, and applied to any information system implementation efforts. At a minimum, the following secure-by-design and privacy-by-design principles shall be applied: **Secure-by-design principles:**

1. Minimize attack surface area
1. Establish secure defaults

1. The principle of least privilege
1. The principle of defense in depth

1. Fail securely
1. Don't trust services

1. Separation of duties
1. Avoid security by obscurity

1. Keep security simple
1. Fix security issues correctly

**Privacy-by-design principles:**

1. Proactive not Reactive; Preventative not Remedial
1. Privacy as the Default Setting

1. Privacy Embedded into Design
1. Full Functionality \- Positive-Sum, not Zero-Sum

1. End-to-End Security \- Full Lifecycle Protection
1. Visibility and Transparency \- Keep it Open

1. Respect for User Privacy \- Keep it User-Centric

Engineering documentation and technical references can be found in the Secure Software Development Process. Software developers are expected to adhere to [COMPANY NAME]'s coding standards throughout the development cycle, including standards for quality, commenting, and security.

## Secure Development Environment

[COMPANY NAME] shall establish and appropriately protect environments for system development and integration efforts that cover the entire system development life cycle. The following environments shall be logically or physically segregated:

- Production
- Staging

- Development

## Outsourced Development

[COMPANY NAME] shall supervise and monitor the activity of outsourced system development. Outsourced development shall adhere to all [COMPANY NAME] standards and policies.

## System Security Testing

Testing of security functionality shall be performed at defined periods during the development life cycle. No code shall be deployed to [COMPANY NAME] production systems without documented, successful test results and evidence of security remediation activities.

## Application Vulnerability Management

Application code should be scanned prior to deployment. Patches to address application vulnerabilities that materially impact security should be deployed within 90 days of discovery.

## System Acceptance Testing

Acceptance testing programs and related criteria shall be established for new information systems, upgrades, and new versions. Prior to deploying code, a Release Checklist MUST be completed which includes a checklist of all Test Plans which show the completion of all associated tests and remediation of identified issues.

## Protection of Test Data

Test data shall be selected carefully, protected, and controlled. Confidential customer data shall be protected in accordance with all contracts and commitments. Customer data must not be used for testing purposes.

## Acquisition of Third-Party Systems and Software

The acquisition of third-party systems and software shall be done in accordance with the requirements of the [COMPANY NAME] Third-Party Management Policy.

## Developer Training

Software developers shall be provided with secure development training appropriate to their role at least annually. Training content shall be determined by management but shall address the prevention of common web application attacks and vulnerabilities. The following threats and vulnerabilities should be addressed as appropriate:

- Prevention of authorization bypass attacks
- Prevention of the use of insecure session IDs

- Prevention of Injection attacks
- Prevention of cross-site scripting attacks

- Prevention of cross-site request forgery attacks
- Prevention of the use of vulnerable libraries

## Exceptions

Requests for an exception to this policy must be submitted to the VP of Engineering for approval.

## Violations & Enforcement

Any known violations of this policy should be reported to the VP of Engineering. Violations of this policy can result in immediate withdrawal or suspension of system and network privileges and/or disciplinary action in accordance with company procedures up to and including termination of employment.
