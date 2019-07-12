# Cisco Intersight Account Reset Tool

The Cisco Intersight Account Reset Tool is designed to increase the efficiency of developers, engineers, sellers and trainers working with Cisco Intersight by automating the Intersight account reset process.

The Cisco Intersight Account Reset Tool will automatically remove any devices, profiles, policies and/or users created under an Intersight account.
By removing the burden of having to manually reset accounts, the Cisco Intersight Account Reset Tool enables more time to be spent on other tasks.
For developers and engineers building applications and platforms for Cisco Intersight, the development and testing process of new features is simplified. 
For sellers and trainers demonstrating the Cisco Intersight product, downtime between customer or student engagements is reduced.
The Cisco Intersight Account Reset Tool also has the ability to exempt specified users and devices from the account reset process.

Use of the Cisco Intersight Account Reset Tool is at your own risk and intended for development, testing, demonstration and training environments. Please do not use on production systems.

## Prerequisites:
1. Python 3 installed, which can be downloaded from https://www.python.org/downloads/.
2. The Cisco Intersight SDK for Python, which can be installed by running:
   ```py
   pip install git+https://github.com/CiscoUcs/intersight-python.git
   ```
   More information on the Cisco Intersight SDK for Python can be found at https://github.com/CiscoUcs/intersight-python.
3. An API key from your Intersight account. To learn how to generate an API key for your Intersight account, more information can be found at https://intersight.com/help/features#rest_apis.

## Getting Started:

1. Please ensure that the above prerequisites have been met.
2. Download the intersight_account_reset_tool.py file for the Cisco Intersight Account Reset Tool from here on GitHub.
3. Edit the intersight_account_reset_tool.py file to set the key_id variable using the following instructions:
   - Open the intersight_account_reset_tool.py file in an IDLE or text editor of choice.
   - Find the comment **"MODULE REQUIREMENT 1"**.
   - Underneath, you will find the variable **key_id = ""**. The variable is currently empty.
   - Fill in between the quotes of the **key_id** variable value with the ID of your API key. For example: 
     ```py
     key_id = "5c89885075646127773ec143/5c82fc477577712d3088eb2f/5c8987b17577712d302eaaff"
     ```
4. Edit the intersight_account_reset_tool.py file to set the key variable using the following instructions:
   - Open the intersight_account_reset_tool.py file in an IDLE or text editor of choice.
   - Find the comment **"MODULE REQUIREMENT 2"**.
   - Underneath, you will find the variable **key = ""**. The variable is currently empty.
   - Fill in between the quotes of the **key** variable value with your system's file path to the SecretKey.txt file for your API key. For example: 
     ```py
     key = "C:\\Keys\\Key1\\SecretKey.txt
     ```
5. Save the changes you have made to the intersight_account_reset_tool.py file.
6. The intersight_account_reset_tool.py file is now ready for use. The file can be ran directly or as a script. See the **"Options:"** section for information on the exempting users or devices under your Intersight account from the reset process.

## Options:
### Exemptions
The Cisco Intersight Account Reset Tool provides the ability to exempt specified users and devices from the Intersight account reset process. The following is a list of the exemptions and how to setup each:

- **User Exemptions** - Excludes specified users from the Intersight account reset process.
  - Open the intersight_account_reset_tool.py file in an IDLE or text editor of choice.
  - Find the comment **"MODULE OPTION 1 - User Exemptions"**.
  - Underneath, you will find the list **exempt_users = []**. The list is currently empty.
  - Fill in between the square brackets of the **exempt_users** list with the email address of any users that should not be removed by the Account Reset Tool. Each email address entry should be separated by a comma. The email address of the user that owns the API key will not be removed by default and is automatically exempted. Leave the list blank if there are no other user exemptions. Here is an example: 
     ```py
     exempt_users = ["user1@email.com", "user2@email.com"]
     ```
   
- **Device Exemptions** - Excludes specified devices from the Intersight account reset process.
    - Open the intersight_account_reset_tool.py file in an IDLE or text editor of choice.
    - Find the comment **"MODULE OPTION 2 - Device Exemptions"**.
    - Underneath, you will find the list **exempt_devices = []**. The list is currently empty.
    - Fill in between the square brackets of the **exempt_devices** list with the hostname, product ID, or serial number of any devices that should not be removed by the Account Reset Tool. Each entry should be separated by a comma. If a hostname or product ID is entered, all devices sharing that same hostname or product ID will be exempted. For Cisco UCS domains with dual Fabric Interconnects, be sure to provide the serial number of each Fabric Interconnect individually. Leave the list blank if there are no device exemptions. Here is an example using serial numbers:
      ```py
      exempt_devices = ["ABV1304000V", "EZL252770MU", "WIA344370GE"]
      ```
    - Combinations of attributes for different devices can also be used as well for exemptions. Here is an example using a serial number, a hostname and a product ID for any Cisco HyperFlex HX220c M5 All Flash server nodes:
      ```py
      exempt_devices = ["ABV1304000V", "hostname1@company.org", "HXAF220C-M5SX"]
      ```

## Author:
Ugo Emekauwa

## Contact Information:
uemekauw@cisco.com or uemekauwa@gmail.com
