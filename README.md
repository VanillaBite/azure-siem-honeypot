# Microsoft Sentinel SOC Lab Project
A project to set up a basic home SOC in Azure using Microsoft Sentinel, a honeypot VM, and real-world attack data analysis.

## Project Overview
This project involves setting up Microsoft Sentinel in a SOC environment using Azure and real attack data. The lab simulates real-world security incidents and prepares for analysis in Sentinel.

## Prerequisites
Before starting this lab, ensure you have:
- An active Azure subscription
- Microsoft Sentinel enabled on your Azure portal
- Basic knowledge of Azure and SOC operations
- The necessary tools and permissions to access Microsoft Sentinel

## Step-by-Step Guide

### Step 1: Setting up the Azure Environment
1. Go to the Azure portal and log in.
2. Create a new **Resource Group** by searching Resource Group in the search bar.
   ![Creating Resource Group]![image](./![image](https://github.com/user-attachments/assets/58349238-c3f9-429f-b8c5-244ea38f57ba)
)![image](./https://github.com/user-attachments/assets/13f4bd58-f6ea-42a8-8c40-344b04cae5de)



3. Deploy **Microsoft Sentinel** in the Resource Group.
   ![Deploying Microsoft Sentinel](./images/deploy-sentinel.png)
4. Set up necessary permissions for accessing Sentinel data.

### Step 2: Configuring Microsoft Sentinel
1. Navigate to Microsoft Sentinel and select your workspace.
2. Connect to data sources (like firewalls, network devices, etc.).
3. Set up data connectors for real attack data, such as Syslog or Windows Event Logs.

### Step 3: Ingesting Real Attack Data
1. Import simulated attack data to test Sentinel's capabilities.
2. Set up a **KQL (Kusto Query Language)** query to filter and analyze the data.

### Step 4: Analyzing Alerts in Sentinel
1. Review alerts triggered by the attack data.
2. Investigate the root cause using Sentinel’s investigation tools.
3. Create custom detection rules based on observed attack patterns.

### Step 5: Finalizing the Lab Setup
1. Create a report summarizing your findings and incident response.
2. Make sure all configurations are saved for future use.

## Conclusion
