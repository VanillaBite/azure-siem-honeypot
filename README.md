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
2. Create a new **Resource Group** by searching Resource Groups in the search bar.
![Screenshot 2025-04-05 204607](./https://github.com/user-attachments/assets/235fd87c-73e3-4a91-a234-ff24e9e843c6) ![Screenshot 2025-04-05 204107](./https://github.com/user-attachments/assets/8699d538-d558-4b3c-99ee-5f67fbf2b211)
3. Create a new Virtual Network, search for Virtual Networks in the search bar and follow previous steps.
4. Create a new Virtual Machines by following the previous steps, be sure to not name it honeypot, name it something innocuous such as 'desktop-01', or 'user-pc-01'.
5. Select an image to use for the VM, choose Windows 10 Pro ![image](./https://github.com/user-attachments/assets/c6b530c0-70ed-4d00-8f5d-067399e8d743)
6. Make sure to choose a VM size you are comfortable with, as well as the OS disk type, I chose to use B1MS, and Standard HDD.
7. Don't forget to select the Virtual Network you created earlier, and to enable deletion of public IP and NIC when VM is deleted. ![image](./https://github.com/user-attachments/assets/94324392-6c0e-4f7a-82b9-3ebad7df3e99)![image](./https://github.com/user-attachments/assets/ab4b1519-0776-481c-bc25-99ffa7f90156)
8. Search Resource Groups and select the name of your lab, it should look like this:![image](./https://github.com/user-attachments/assets/976511d8-3289-4c3f-b33a-e5e156a46c31)
9. Next we will need to edit the network security group, we are going to make this device vulnerable to the internet by opening up the firewall which will allow any traffic to have access. To do this, select 'corp-net-east-01-nsg' ![image](./https://github.com/user-attachments/assets/a0082dd3-5266-4164-97b4-c7e236fb68ea) and delete security rule RDP.
10. Go to Settings, then Inbound Security rules, we are going to add the rule that allows any traffic in: ![image](./https://github.com/user-attachments/assets/f590a3d3-27e2-439f-b2b6-57df71424da2)
11. To disable the Windows Firewall you need to connect to the VM, ![image](./https://github.com/user-attachments/assets/404c6bce-b5ad-48c7-b1f7-cdcfaf131e81), search for Firewall & network protection, and turn all those settings off ![image](./https://github.com/user-attachments/assets/23bd8653-288a-49a6-bd38-6ced3bde4d79).
12. To confirm if everything is working, ping the public IP address of your VM from your local machine.
    
    Triggering Event Logs (Optional but Recommended):
To simulate authentication-related activity and verify that event logging is working correctly, try intentionally entering incorrect login credentials into your VM a few times.
You should then see these failed login attempts logged under:
Windows Logs > Security
Event ID: 4625 (An account failed to log on) ![image](./https://github.com/user-attachments/assets/0d89cf6a-148a-4363-b8e1-c6408513e06f)

Note: This is a safe way to generate activity and helps confirm your SIEM is capturing security events accurately.

## Log Activity from Public VM Access

Since we’ve opened this VM to the public internet, it’s very likely that random people (or bots) will try to log in. These attempts will get logged automatically in the Windows Event Viewer.

In the next part of the lab, we’ll forward those logs to Azure so we can work with them inside Microsoft Sentinel. This way, we can start building queries, spotting suspicious activity, and getting hands-on with how a real SIEM works.

### Step 2: Configuring Microsoft Sentinel
1. In Azure, type Log Analytics Workspace and create! ![image](./https://github.com/user-attachments/assets/8de90ad2-73b4-4a9b-8529-4a63d07cb103)
2. Next search for Microsoft Sentinel and add it to the lab.
3. Then we need to install the Windows Security Events through Sentinel, make sure to click 'manage' afterwards. ![image](./https://github.com/user-attachments/assets/a2080697-2f97-4323-878a-3cea542edb47)
4. We are going to then enable Windows Security Events via AMA and open the connector page![image](./https://github.com/user-attachments/assets/52c645ae-03a8-4c18-beae-6437eebec681) and create a data collection rule! ![image](./https://github.com/user-attachments/assets/ba977af9-c075-468e-b43b-5935acf69533) Be sure to click everything for the scope and leave the rest as default.   
(This rule is used by the virtual machine to forward logs into our log analytics workspace, which lets us access them inside of our SIEM)
6. Go back to Log Analytics Workspace and select the lab, go into logs and query SecurityEvent to see all records, you can also narrow down what information should be presented ![image](./https://github.com/user-attachments/assets/5cf86c07-a5e5-4abb-bec2-0edd2fcefb79)![image](./https://github.com/user-attachments/assets/175163f6-f2e1-4862-8eac-7432b5dc9d0a). There are more examples below!


   Narrowing Down Log Analysis:

This query identifies successful logins from IP addresses that aren’t part of your normal network range. ![image](./https://github.com/user-attachments/assets/2264511a-cf9d-4a91-ad1c-0fdd5890f459)

SecurityEvent
| where EventID == 4624 // Successful login
| where IpAddress != "192.168.1.100" // Exclude your own IP address
| where TimeGenerated > ago(1d) // Filter to recent logins
| project TimeGenerated, Account, IpAddress, LogonType
| order by TimeGenerated desc

These queries identify multiple failed log on attempts. ![image](./https://github.com/user-attachments/assets/4a20fc56-1b7d-41c1-ba57-0794719174be) ![image](./https://github.com/user-attachments/assets/109ab33b-d7e6-4996-9bb2-c4f04d4f8546)


SecurityEvent
| where EventID == 4625 // Failed login attempts
| summarize FailedLogins = count() by Account, IpAddress
| order by FailedLogins desc

SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress

7. Next the goal is to create a WatchList, go back into MicrosoftSentinel, scroll down onto Configuration and select Watchlist ![image](./https://github.com/user-attachments/assets/727486f7-7bf6-404b-927e-dffee0ccfe32).
Make sure the name and alias are the same, I chose to name them 'geoip', and on the next page upload this file [(https://drive.google.com/file/d/13EfjM_4BohrmaxqXZLB5VUBIz2sv9Siz/view?usp=sharing)].](https://drive.google.com/file/d/13EfjM_4BohrmaxqXZLB5VUBIz2sv9Siz/view?usp=sharing)
For the SearchKey choose network, your WatchList should look like this: ![image](./https://github.com/user-attachments/assets/68ce502c-46db-4976-b1b3-5e43765759bc)
![image](./https://github.com/user-attachments/assets/73fad1c2-c59d-4b17-9876-0532bf52b544)

Now we can see where the failed log in attempts are coming from! ![image](./https://github.com/user-attachments/assets/a2d4fb2f-bed0-4ca5-94fc-c7b2028fe4c8)

Run this KQL script to get an easy to understand result of where attackers are located, when the attack occurred, the name of the attackers, etc.. ![image](./https://github.com/user-attachments/assets/1caaec0d-ff97-420f-8d28-431ac8611e7e)

let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "27.102.71.18"
    | where EventID == 4625
    | order by TimeGenerated desc 
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
| project TimeGenerated, Computer, AttackerIp = IpAddress, cityname, countryname, latitude, longitude;

9. The last thing to do here is to create a visual through Sentinel so we can see on a map where the attackers are coming from. We can do this by creating a WorkBook, you can find this under Threat Management. ![image](./https://github.com/user-attachments/assets/b9ba1c9c-b758-4250-922f-d21b7eb73e2d)
10. Then we remove the elements that the WorkBook was prepopulated with, and add a new query, make sure to also paste this query into the Advanced Editor.
    
    {
	"type": 3,
	"content": {
	"version": "KqlItem/1.0",
	"query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
	"size": 3,
	"timeContext": {
		"durationMs": 2592000000
	},
	"queryType": 0,
	"resourceType": "microsoft.operationalinsights/workspaces",
	"visualization": "map",
	"mapSettings": {
		"locInfo": "LatLong",
		"locInfoColumn": "countryname",
		"latitude": "latitude",
		"longitude": "longitude",
		"sizeSettings": "FailureCount",
		"sizeAggregation": "Sum",
		"opacity": 0.8,
		"labelSettings": "friendly_location",
		"legendMetric": "FailureCount",
		"legendAggregation": "Sum",
		"itemColorSettings": {
		"nodeColorField": "FailureCount",
		"colorAggregation": "Sum",
		"type": "heatmap",
		"heatmapPalette": "greenRed"
		}
	}
	},
	"name": "query - 0"
}

11. When all that is finished the final product should look similar to [![this](./images/screenshot.png)](https://github.com/user-attachments/assets/36e45261-c57e-4bd0-b1be-8fb1d514e582)

     What this query is doing is counting up the different login failures where the longitude, latitude, city, and country are the same and plotting them on the map!

### Step 3 Detection and Incident Response
In this step, we will set up analytical rules in Microsoft Sentinel to trigger alerts for suspicious activities, like brute force login attempts, and automatically create incidents when those alerts are triggered.

To do this we go to Microsoft Sentinel and go to the Analytics tab, then click on "+ Create" --> "Scheduled query rule" 

If we want to create a rule for Brute Force Attempt Detection input use [![these settings](./images/screenshot.png)](https://github.com/user-attachments/assets/32b4d054-775f-4ae9-af72-b2044f5081cc)]) for MITRE ATT&CK.

After we implement those settings, click on "Set Rule Logic" and input this KQL script!

SecurityEvent
| where EventID == 4625  // Event ID for failed logon attempts
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5  // Customize the threshold for your needs
| project TimeGenerated, Account, IpAddress, FailedAttempts
| order by TimeGenerated desc

it should appear as [![this](./images/screenshot.png)](https://github.com/user-attachments/assets/ab51a211-f46d-44b3-baa2-eb4ef27469ce)]) afterwards.

This query identifies multiple failed login attempts within a set time period (e.g., 5 failed logins in 10 minutes) from the same account or IP address.

This setup will alert you whenever there are repeated failed login attempts, helping you detect potential brute-force attacks or suspicious activity

### Conclusion

In this project, we successfully set up Microsoft Sentinel to detect brute-force login attempts on a virtual machine running in Azure. By leveraging Log Analytics, KQL queries, and analytical rules, we were able to monitor failed login attempts, detect suspicious activities, and automatically trigger incidents for further investigation.

[![click here](./images/screenshot.png)](https://github.com/user-attachments/assets/ab51a211-f46d-44b3-baa2-eb4ef27469ce)




