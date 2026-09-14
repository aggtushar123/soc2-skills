# Business Continuity and Disaster Recovery Plan

## Purpose

The aim of this business continuity plan is to prepare [COMPANY NAME] for service outages due to uncontrollable factors (e.g., natural disasters, man-made events) and to restore services as broadly and quickly as possible.

## Scope

This policy covers all [COMPANY NAME] IT systems critical to business operations. It applies to all [COMPANY NAME] employees and relevant external parties, including consultants and contractors. Excluded scenarios:

- Loss of availability for a production hosting service provider (e.g., AWS).
- Loss of availability of [COMPANY NAME] satellite offices (considered incidents).

If a hosting service provider becomes unavailable, CISO will collaborate with the CEO, Head of Engineering \[Development Contractors\] and Product Manager to formulate a response strategy.

## Policy

In case of a major disruption to production services or a disaster affecting the availability or security of the [COMPANY NAME] office, senior management will decide on mitigation actions. An annual disaster recovery test, including backup restoration processes, is required. Information security continuity must be considered alongside operational continuity. Refer to the Incident Response Plan for information security events or incidents.

## Alternate Work Facilities

If the [COMPANY NAME] staff member’s office is inaccessible due to a disaster, the staff member will seek to work remotely from any other safe location.

## Communications and Escalation

Executive staff and senior managers must be informed of any disaster affecting [COMPANY NAME] facilities or operations. Communications should use regular channels such as Slack, email, and phone. Key contacts should be maintained on the on-call schedule.

## Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Fractional CISO | Leads BC/DR efforts to mitigate losses and recover corporate network and information systems. |
| Departmental Heads | Responsible for departmental staff communication and maintaining business function continuity. Regular communication with executive staff and the Product Manager is required. Communicate with direct reports and assist staff in working from alternate locations. |
| Engineering and DevOps Team Members | With the departmental heads, leads efforts to maintain service continuity to customers during a disaster. |
| CEO | Handles internal and external communications and actions needed to maintain workforce health and safety. |

## Continuity of Critical Services

Procedures for maintaining continuity of critical services during a disaster are detailed in Appendix A. Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) are listed in Appendix B. The strategy for maintaining service continuity is outlined below:

| KEY BUSINESS PROCESS | CONTINUITY STRATEGY |
|---|---|
| Customer (Production) Service Delivery | Rely on cloud hosting provider availability commitments and SLAs. |
| IT Operations | Not dependent on HQ. Critical data is backed up to alternate locations. |
| Email | Utilize email provider's distributed nature, relying on provider SLAs. |
| Finance, Legal, and HR | All systems are vendor-hosted SaaS applications (external systems). |
| Sales and Marketing | All systems are vendor-hosted SaaS applications (external systems). |

## Plan Activation

This BC/DR plan will automatically activate in the event of the [COMPANY NAME] office or products becoming unavailable or a natural disaster (e.g., severe weather, regional power outage, earthquake).
