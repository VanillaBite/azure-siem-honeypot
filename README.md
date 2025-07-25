# Microsoft Sentinel SOC Lab Project
A project to set up a basic home SOC in Azure using Microsoft Sentinel, a honeypot VM, and real-world attack data analysis.

## Project Overview
This project focuses on building a functional Security Operations Center (SOC) lab using Microsoft Sentinel. The goal was to successfully monitor and analyze real-time cyberattacks targeting a virtual machine hosted in Azure. I set up Microsoft Sentinel, connected it to Log Analytics, and used Kusto Query Language (KQL) to detect suspicious behavior in the logs—primarily brute-force login attempts.

Throughout the project, I created analytical rules to generate alerts based on specific patterns of attack, which helped simulate a real-world SOC environment. This hands-on experience gave me deeper insight into threat detection, incident management, and working with SIEM tools in the cloud.

## Prerequisites
Before starting this lab, ensure you have:
- An active Azure subscription
- Microsoft Sentinel enabled on your Azure portal
- Basic knowledge of Azure and SOC operations
- The necessary tools and permissions to access Microsoft Sentinel

## Step-by-Step Guide 

### Step 1: Setting up the Azure Environment
- Go to the Azure portal and log in.
- Create a new **Resource Group** by searching Resource Groups in the search [bar](./screenshots/im3.png) and [click here](./images/im2.png)
- Create a new Virtual Network, search for Virtual Networks in the search bar and follow previous steps.
- Create a new Virtual Machines by following the previous steps, be sure to not name it honeypot, name it something innocuous such as 'desktop-01', or 'user-pc-01'.
- Select an image to use for the VM, choose Windows 10 [Pro](./images/im4.png)
- Make sure to choose a VM size you are comfortable with, as well as the OS disk type, I chose to use B1MS, and Standard HDD.
- Don't forget to select the Virtual Network you created earlier, and to enable deletion of public IP and NIC when VM is deleted. [shown here](./images/im5.png) and [here](./images/im6.png)
- Search Resource Groups and select the name of your lab, it should look like [this](./images/im61.png)
- Next we will need to edit the network security group, we are going to make this device vulnerable to the internet by opening up the firewall which will allow any traffic to have access. To do this, select 'corp-net-east-01-nsg' [here](./images/im1.png) and delete security rule RDP.
- Go to Settings, then Inbound Security rules, we are going to add the rule that allows any traffic [in](./images/im7.png)
- To disable the Windows Firewall you need to connect to the [VM](./images/im8.png), search for Firewall & network protection, and turn all those settings [off](./images/im9.png)
- To confirm if everything is working, ping the public IP address of your VM from your local machine.
    
    Triggering Event Logs (Optional but Recommended):
To simulate authentication-related activity and verify that event logging is working correctly, try intentionally entering incorrect login credentials into your VM a few times.
You should then see these failed login attempts logged under:
Windows Logs > Security
Event ID: 4625 (An account failed to log on) [event logs](./images/im10.png)

Note: This is a safe way to generate activity and helps confirm your SIEM is capturing security events accurately.

## Log Activity from Public VM Access

Since we’ve opened this VM to the public internet, it’s very likely that random people (or bots) will try to log in. These attempts will get logged automatically in the Windows Event Viewer.

In the next part of the lab, we’ll forward those logs to Azure so we can work with them inside Microsoft Sentinel. This way, we can start building queries, spotting suspicious activity, and getting hands-on with how a real SIEM works.

### Step 2: Configuring Microsoft Sentinel
- In Azure, type Log Analytics Workspace and [create](./images/im62.png)
- Next search for Microsoft Sentinel and add it to the lab.
- Then we need to install the Windows Security Events through Sentinel, make sure to click 'manage' [afterwards](./images/im12.png)
- We are going to then enable Windows Security Events via AMA and open the connector [page](./images/im13.png) and create a data collection [rule](./images/im15.png) Be sure to click everything for the scope and leave the rest as default.   
(This rule is used by the virtual machine to forward logs into our log analytics workspace, which lets us access them inside of our SIEM)
- Go back to Log Analytics Workspace and select the lab, go into logs and query [SecurityEvent](./images/im16.png) to see all records, you can also narrow down what information should be [presented](./images/im20.png). There are more examples below!


   Narrowing Down Log Analysis:

This query identifies successful logins from IP addresses that aren’t part of your normal network [range.](./images/im18.png)

SecurityEvent
| where EventID == 4624 // Successful login
| where IpAddress != "192.168.1.100" // Exclude your own IP address
| where TimeGenerated > ago(1d) // Filter to recent logins
| project TimeGenerated, Account, IpAddress, LogonType
| order by TimeGenerated desc

These queries identify multiple failed log on attempts [here](./images/im21.png)


SecurityEvent
| where EventID == 4625 // Failed login attempts
| summarize FailedLogins = count() by Account, IpAddress
| order by FailedLogins desc

SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress

- Next the goal is to create a WatchList, go back into MicrosoftSentinel, scroll down onto Configuration and select [Watchlist](./images/screenshot.png).
   
Make sure the name and alias are the same, I chose to name them 'geoip', and on the next page upload this file [(https://drive.google.com/file/d/13EfjM_4BohrmaxqXZLB5VUBIz2sv9Siz/view?usp=sharing)].](https://drive.google.com/file/d/13EfjM_4BohrmaxqXZLB5VUBIz2sv9Siz/view?usp=sharing)

For the SearchKey choose network, your WatchList should look like [this](./images/screenshot.png) and
[this](./images/screenshot.png)

Now we can see where the failed log in attempts are coming [from!](./images/screenshot.png)

Run this KQL script to get an easy to understand result of where attackers are located, when the attack occurred, the name of the attackers, [etc..](./images/screenshot.png)

let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "27.102.71.18"
    | where EventID == 4625
    | order by TimeGenerated desc 
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
| project TimeGenerated, Computer, AttackerIp = IpAddress, cityname, countryname, latitude, longitude;

- The last thing to do here is to create a visual through Sentinel so we can see on a map where the attackers are coming from. We can do this by creating a WorkBook, you can find this under [Threat Management](./images/screenshot.png)
    
- Then we remove the elements that the WorkBook was prepopulated with, and add a new query, make sure to also paste this query into the Advanced Editor.
    
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

- When all that is finished the final product should look similar to [this](./images/screenshot.png)

     What this query is doing is counting up the different login failures where the longitude, latitude, city, and country are the same and plotting them on the map!

### Step 3: Detection and Incident Response
In this step, we will set up analytical rules in Microsoft Sentinel to trigger alerts for suspicious activities, like brute force login attempts, and automatically create incidents when those alerts are triggered.

To do this we go to Microsoft Sentinel and go to the Analytics tab, then click on "+ Create" --> "Scheduled query rule" 

If we want to create a rule for Brute Force Attempt Detection input use [these settings](./images/screenshot.png)

After we implement those settings, click on "Set Rule Logic" and input this KQL script!

SecurityEvent
| where EventID == 4625  // Event ID for failed logon attempts
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5  // Customize the threshold for your needs
| project TimeGenerated, Account, IpAddress, FailedAttempts
| order by TimeGenerated desc

It should appear as [this](./images/screenshot.png)

This query identifies multiple failed login attempts within a set time period (e.g., 5 failed logins in 10 minutes) from the same account or IP address.

This setup will alert you whenever there are repeated failed login attempts, helping you detect potential brute-force attacks or suspicious activity

### Conclusion

In this project, we successfully set up Microsoft Sentinel to detect brute-force login attempts on a virtual machine running in Azure. By leveraging Log Analytics, KQL queries, and analytical rules, we were able to monitor failed login attempts, detect suspicious activities, and automatically trigger incidents for further investigation.




