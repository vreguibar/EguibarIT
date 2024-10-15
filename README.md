# EguibarIT

[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/EguibarIT.svg)](https://www.powershellgallery.com/packages/EguibarIT)
[![PowerShell Gallery Preview Version](https://img.shields.io/powershellgallery/vpre/EguibarIT.svg?label=powershell%20gallery%20preview&colorB=yellow)](https://www.powershellgallery.com/packages/EguibarIT)
![GitHub Release](https://img.shields.io/github/v/release/vreguibar/EguibarIT)
[![GitHub License](https://img.shields.io/github/license/vreguibar/EguibarIT.svg)](https://github.com/vreguibar/EguibarIT)

[![PowerShell Gallery](https://img.shields.io/powershellgallery/p/EguibarIT.svg)](https://www.powershellgallery.com/packages/EguibarIT)
![GitHub language count](https://img.shields.io/github/languages/count/vreguibar/EguibarIT)
[![GitHub Top Language](https://img.shields.io/github/languages/top/vreguibar/EguibarIT.svg)](https://github.com/vreguibar/EguibarIT)
[![GitHub Code Size](https://img.shields.io/github/languages/code-size/vreguibar/EguibarIT.svg)](https://github.com/vreguibar/EguibarIT)
[![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/EguibarIT.svg)](https://www.powershellgallery.com/packages/EguibarIT)

![GitHub Sponsors](https://img.shields.io/github/sponsors/vreguibar)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-VicenteRodriguezEguibar-0077B5.svg?logo=LinkedIn)](https://www.linkedin.com/in/VicenteRodriguezEguibar)

Root module for creating Tier Model / Delegation Model on Active Directory

More information on this can be found on:

    www.EguibarIT.com
    www.DelegationModel.com
    www.TierModel.com

This module contains the basic functions used to create the Delegation Model / Tier Model / RBAC model for Active Directory.

## Overview

The module includes functions for managing roles, permissions, and delegation across different organizational units, improving Active Directory security and delegation management. Ideal for organizations implementing a tiered administrative model or requiring efficient RBAC practices.

It is a collection of advanced administrative tools designed to streamline the management of Active Directory environments by helping implement the Delegation Model and Tier Model. This module offers a suite of automation capabilities for such implementation, while adhering to best practices in PowerShell development and security.

The EguibarIT module,  provides an essential toolkit for implementing Tier Models, Delegation Models, and Role-Based Access Control (RBAC) structures within Active Directory environments. It simplifies the creation of administrative structures such as:

* Administration OU (Tier 0)
* Groups representing the roles created on Administration OU
* Servers OU (Tier 1)
* Sites OU (Tier 2)

The EguibarIT module is a powerful tool designed to enhance Active Directory (AD) management by automating key aspects of tiered and delegation models. It's especially useful in environments that need to implement security-focused Tier Models (e.g., Tier 0 for highly sensitive administrative tasks, Tier 1 for servers, and Tier 2 for workstations or user roles).

## Benefits:
Enhanced Security: Automates RBAC and tiered structures to enforce security policies.
Streamlined Delegation: Simplifies role-based delegation of AD tasks.
Automated Provisioning: Configures Organizational Units (OUs), delegation permissions, and groups based on industry best practices.
Error Handling & Reporting: Built-in functions to ensure smooth operation and easy troubleshooting.

## Recommended Use Cases:
Deploying Tiered Administration Models: When securing your AD by splitting administrative functions into distinct security tiers.
Implementing Delegation Models: When needing to delegate specific AD permissions to different teams or roles, without over-provisioning privileges.
Automating Group Policy Management: When automating and managing Group Policy Object (GPO) configurations for consistent security enforcement.
Auditing AD Security: When performing security audits, such as generating security reports on delegation, memberships, and permissions.

### Usage in Different Scenarios:
* Large Enterprises: Ideal for organizations managing hundreds or thousands of users across multiple domains, requiring strict role-based access control.
* Security Audits: For AD environments where security is paramount, the module provides tools to audit and report on security configurations, ensuring compliance with internal policies or external standards (e.g., ISO/IEC 27001).
* Delegation of Control: Allows administrators to delegate specific administrative tasks to junior admins or regional IT staff without compromising higher-tier privileges.

This module simplifies the often complex task of implementing tier-based and delegated administration models, providing a structured, efficient, and secure framework for AD management.

## Core Features and Functions
This module provides several key functionalities tailored to Active Directory, including:

* Delegation and Security Role Management: The core of this module is built around the Delegation Model and the Tier Model. These models allow for secure, hierarchical administration by limiting access based on role-specific responsibilities. Instead of assigning high-privilege groups like Domain Admins or Enterprise Admins, tasks are delegated to more granular, controlled levels of access. This prevents excessive permissions and mitigates potential security risks.

* Tiered Administration: Utilizing the Tier Model, environments are segmented into different operational zones (e.g., Tier 0 for critical domain objects, Tier 1 for server management, and Tier 2 for user and endpoint devices). This segmentation ensures that sensitive credentials remain isolated within the appropriate operational context.

* Automated Group Policy Management: Functions to facilitate the management of Group Policy Objects (GPOs), streamlining the configuration process and reducing human error, which is critical in highly controlled environments.

* Least Privileged Access Enforcement: With built-in support for managing Privileged Access Workstations (PAWs), Service Accounts, and Infrastructure Servers, the module enforces the principle of least privilege. This ensures that no administrator or system component has more access than necessary for its role.

## Why Use the EguibarIT Module?
1. Security & Compliance:
The module is designed to help organizations implement security best practices, aligning with frameworks such as Microsoft's Privileged Access Workstations (PAWs) and the Zero Trust architecture. By leveraging the RBAC-based delegation model, it enables companies to delegate tasks while minimizing the risk of privilege escalation. The Tier Model ensures strict credential isolation, thereby protecting sensitive accounts from being compromised through lateral movement.

2. Simplified Management:
Managing complex Active Directory environments becomes streamlined with this module, thanks to its automated and reusable delegation frameworks. By reducing the complexity of administrative tasks, organizations can lower operational costs and reduce the risk of human error. Simplifying the management of Group Policies, User Rights Assignments, and Service Accounts significantly enhances efficiency, allowing for faster deployment and maintenance of security policies.

3. Flexibility:
The modular design of EguibarIT allows for its integration into various Active Directory structures. Whether your environment requires fine-grained delegation or large-scale infrastructure management, this toolset is built to accommodate both, with full support for scalable operations.

4. Future-Proofing:
The EguibarIT module keeps your AD infrastructure adaptable to future security challenges. Its model-driven approach to administration makes it easier to implement new security policies without having to overhaul the entire AD structure. With a focus on automation, you can be confident in its ability to evolve alongside industry standards.

## Usage

Install and use the module for all users.

```powershell

To install the EguibarIT module, you can download it from the PowerShellGallery (or Github by cloning) and import it into your PowerShell session:

Find-Module EguibarIT | InstallModule -Scope AllUsers -Force

Import-Module EguibarIT
