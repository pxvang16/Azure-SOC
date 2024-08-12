# Building a SOC + Honeynet in Azure (Live Traffic)
![SOC](https://github.com/user-attachments/assets/0c924d64-1b94-4e54-8775-15b0f2a4febc)


## Introduction

For this project, I develop a small Azure honeynet and ingest log data from several sources into a workspace designated Log Analytics. Microsoft Sentinel then uses this workspace to create incidents, generate alerts, and create attack maps. After applying certain security controls to harden the environment and measuring security metrics for a further 24 hours in the unsecure environment, I presented the data below. The measurements we'll display are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture Before Hardening / Security Controls
![Public Internet](https://github.com/user-attachments/assets/e6e0f525-a83e-4438-9ca9-fe727925f12a)


## Architecture After Hardening / Security Controls
![After Hardning Public](https://github.com/user-attachments/assets/85fc7535-ae56-4b82-bbd5-11bb7cb49d42)


The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The virtual machines built-in firewalls and network security groups were both left wide open, and all other resources were set up with their public endpoints open to the public Internet.

For the "AFTER" metrics, all resources were safeguarded by their built-in firewalls and Private Endpoint, and Network Security Groups were toughened by preventing ALL traffic except from my admin workstation.

## Attack Maps Before Hardening / Security Controls
![NSG-Malicious](https://github.com/user-attachments/assets/286b0afb-ccf0-4496-9286-fcc0c4783110)
![linux](https://github.com/user-attachments/assets/49636fb9-1c36-441b-8f5e-16a873401f22)
![windows-rdp](https://github.com/user-attachments/assets/0bfdf960-f7d8-4c3d-916e-1b60487c7354)

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2024-07-24 14:04:29
Stop Time 2024-07-25 14:04:29

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 15334
| Syslog                   | 3988
| SecurityAlert            | 9
| SecurityIncident         | 176
| AzureNetworkAnalytics_CL | 1109

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2024-07-27 15:37
Stop Time	2024-07-28 15:37

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 1100
| Syslog                   | 344
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Conclusion

This project involved building a honeynet in Microsoft Azure and integrating log sources into a Log Analytics Workspace. Based on the ingested data, Microsoft Sentinel was used to generate incidents and trigger alerts. Furthermore, measurements were taken in the compromised environment both before and after security safeguards were put in place. Notably, the implementation of security measures resulted in a significant decrease in the quantity of security events and incidents, indicating they were effective.

It is worth noting that if the resources within the network were heavily utilized by regular users, it's possible that during the first 24 hours after the security controls were put in place, more security events and alerts were created.
