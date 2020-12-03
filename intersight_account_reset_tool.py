"""
Cisco Intersight Account Reset Tool, v2.0
Author: Ugo Emekauwa
Contact: uemekauw@cisco.com, uemekauwa@gmail.com
Summary: The Cisco Intersight Account Reset Tool automates the process
          of cleaning up and resetting a Cisco Intersight account used 
          for development, testing, demonstration and training purposes.
"""

# Import needed Python modules
import sys
import json
import os
import intersight
from intersight.intersight_api_client import IntersightApiClient

# Starting the Cisco Intersight Account Reset Tool
print("Starting the Cisco Intersight Account Reset Tool.\n")


# MODULE REQUIREMENT 1
"""
For the following variable below named key_id, please fill in between
the quotes your Intersight API Key ID.

Here is an example: key_id = "5c89885075646127773ec143/5c82fc477577712d3088eb2f/5c8987b17577712d302eaaff"
"""
key_id = ""


# MODULE REQUIREMENT 2
"""
For the following variable below named key, please fill in between
the quotes your system's file path to your Intersight API key "SecretKey.txt" file.

Here is an example: key = "C:\\Keys\\Key1\\SecretKey.txt"
"""
key = ""


# MODULE OPTION 1 - User Exemptions
"""
For the following list below named exempt_users, please fill in between
the square brackets the email address of any users that should not be removed
by the Account Reset Tool. Each email address entry should be separated by a comma.
The email address of the user that owns the API key will not be removed by default
and is automatically exempted.

Leave the list blank if there are no other user exemptions.

Here is an example: exempt_users = ["user1@email.com", "user2@email.com"]
"""
exempt_users = []


# MODULE OPTION 2 - Device Exemptions
"""
For the following list below named exempt_devices, please fill in between
the square brackets with the hostname, product ID, or serial number of any devices
that should not be removed by the Account Reset Tool. Each entry should be separated
by a comma. If a hostname or product ID is entered, all devices sharing that same
hostname or product ID will be exempted.

For UCS domains with dual fabric interconnects, be sure to provide the
serial number of each fabric interconnect individually.

Leave the list blank if there are no device exemptions.

Here is an example: exempt_devices = ["ABV1304000V", "EZL252770MU", "WIA344370GE"]
"""
exempt_devices = []


# Define Intersight SDK IntersightApiClient variables
# Tested on Cisco Intersight API Reference v1.0.9-2440
base_url = "https://intersight.com/api/v1"
api_instance = IntersightApiClient(host=base_url,private_key=key,api_key_id=key_id)

# Establish Intersight Universal Functions

def iu_get(api_path):
  """This is a function to perform a universal or generic GET on objects under available Intersight API types,
  including those not yet defined in the Intersight SDK for Python. An argument for the API type path is required.

  Args:
    api_path: The path to the targeted Intersight API type. For example, to specify the Intersight API type for
      adapter configuration policies, enter "adapter/ConfigPolicies". More API types can be found in the Intersight
      API reference library at https://intersight.com/apidocs/introduction/overview/.

  Returns:
    A dictionary containing all objects of the specified API type. If the API type is inaccessible, an
    implicit value of None will be returned.
  """
  full_resource_path = "/" + api_path
  try:
    api_instance.call_api(full_resource_path,"GET")
    response = api_instance.last_response.data
    results = json.loads(response)
    print("The API resource path '" + api_path + "' has been accessed successfully.")
    return results
  except:
    print("Unable to access the API resource path '" + api_path + "'.")


def iu_get_moid(api_path,moid):
  """This is a function to perform a universal or generic GET on a specified object under available
  Intersight API types, including those not yet defined in the Intersight SDK for Python. An argument for the
  API type path and MOID (managed object identifier) is required.
  
  Args:
    api_path: The path to the targeted Intersight API type. For example, to specify the Intersight API type for
      adapter configuration policies, enter "adapter/ConfigPolicies". More API types can be found in the Intersight
      API reference library at https://intersight.com/apidocs/introduction/overview/.
    moid: The managed object ID of the targeted API object.

  Returns:
    A dictionary containing all parameters of the specified API object. If the API object is inaccessible, an
    implicit value of None will be returned.
  """
  full_resource_path = "/" + api_path + "/" + moid
  try:
    api_instance.call_api(full_resource_path,"GET")
    response = api_instance.last_response.data
    results = json.loads(response)
    print("The object located at the resource path '" + full_resource_path + "' has been accessed succesfully.")
    return results
  except:
    print("Unable to access the object located at the resource path '" + full_resource_path + "'.")


def iu_delete_moid(api_path,moid):
  """This is a function to perform a universal or generic DELETE on a specified object under available
  Intersight API types, including those not yet defined in the Intersight SDK for Python. An argument for the
  API type path and MOID (managed object identifier) is required.
    
  Args:
    api_path: The path to the targeted Intersight API type. For example, to specify the Intersight API type for
      adapter configuration policies, enter "adapter/ConfigPolicies". More API types can be found in the Intersight
      API reference library at https://intersight.com/apidocs/introduction/overview/.
    moid: The managed object ID of the targeted API object.

  Returns:
    A statement indicating whether the DELETE method was successful or failed.
  
  Raises:
    Exception: An exception occured while performing the API call. The exact error will be
    specified.
  """
  full_resource_path = "/" + api_path + "/" + moid
  try:
    api_instance.call_api(full_resource_path,"DELETE")
    print("The deletion of the object located at the resource path '" + full_resource_path + "' has been completed.")
    return "The DELETE method was successful."
  except Exception as exception_message:
    print("Unable to access the object located at the resource path '" + full_resource_path + "'.")
    print(exception_message)
    return "The DELETE method failed."


def iu_post(api_path,body):
  """This is a function to perform a universal or generic POST of an object under available Intersight
  API types, including those not yet defined in the Intersight SDK for Python. An argument for the
  API type path and body configuration data is required.
  
  Args:
    api_path: The path to the targeted Intersight API type. For example, to specify the Intersight API type for
      adapter configuration policies, enter "adapter/ConfigPolicies". More API types can be found in the Intersight
      API reference library at https://intersight.com/apidocs/introduction/overview/.
    body: The content to be created under the targeted API type. This should be provided in a dictionary format.
  
  Returns:
    A statement indicating whether the POST method was successful or failed.
    
  Raises:
    Exception: An exception occured while performing the API call. The exact error will be
    specified.
  """
  full_resource_path = "/" + api_path
  try:
    api_instance.call_api(full_resource_path,"POST",body=body)
    print("The creation of the object under the resource path '" + full_resource_path + "' has been completed.")
    return "The POST method was successful."
  except Exception as exception_message:
    print("Unable to create the object under the resource path '" + full_resource_path + "'.")
    print(exception_message)
    return "The POST method failed."


def iu_post_moid(api_path,moid,body):
  """This is a function to perform a universal or generic POST of a specified object under available Intersight
  API types, including those not yet defined in the Intersight SDK for Python. An argument for the
  API type path, MOID (managed object identifier), and body configuration data is required.
      
  Args:
    api_path: The path to the targeted Intersight API type. For example, to specify the Intersight API type for
      adapter configuration policies, enter "adapter/ConfigPolicies". More API types can be found in the Intersight
      API reference library at https://intersight.com/apidocs/introduction/overview/.
    moid: The managed object ID of the targeted API object.
    body: The content to be modified on the targeted API object. This should be provided in a dictionary format.
  
  Returns:
    A statement indicating whether the POST method was successful or failed.
    
  Raises:
    Exception: An exception occured while performing the API call. The exact error will be
    specified.
  """
  full_resource_path = "/" + api_path + "/" + moid
  try:
    api_instance.call_api(full_resource_path,"POST",body=body)
    print("The update of the object located at the resource path '" + full_resource_path + "' has been completed.")
    return "The POST method was successful."
  except Exception as exception_message:
    print("Unable to access the object located at the resource path '" + full_resource_path + "'.")
    print(exception_message)
    return "The POST method failed."


def iu_patch_moid(api_path,moid,body):
  """This is a function to perform a universal or generic PATCH of a specified object under available Intersight
  API types, including those not yet defined in the Intersight SDK for Python. An argument for the
  API type path, MOID (managed object identifier), and body configuration data is required.
      
  Args:
    api_path: The path to the targeted Intersight API type. For example, to specify the Intersight API type for
      adapter configuration policies, enter "adapter/ConfigPolicies". More API types can be found in the Intersight
      API reference library at https://intersight.com/apidocs/introduction/overview/.
    moid: The managed object ID of the targeted API object.
    body: The content to be modified on the targeted API object. This should be provided in a dictionary format.
  
  Returns:
    A statement indicating whether the PATCH method was successful or failed.
    
  Raises:
    Exception: An exception occured while performing the API call. The exact error will be
    specified.
  """
  full_resource_path = "/" + api_path + "/" + moid
  try:
    api_instance.call_api(full_resource_path,"PATCH",body=body)
    print("The update of the object located at the resource path '" + full_resource_path + "' has been completed.")
    return "The PATCH method was successful."
  except Exception as exception_message:
    print("Unable to access the object located at the resource path '" + full_resource_path + "'.")
    print(exception_message)
    return "The PATCH method failed."


# Establish function to test for the availability of the Intersight API and Intersight account

def test_intersight_service():
  """This is a function to test the availability of the Intersight API and Intersight account. The Intersight account
  tested for is the owner of the provided Intersight API key and key ID.
  """
  try:
    # Check that Intersight Account is accessible
    print("Testing access to the Intersight API by verifying the Intersight account information...")
    check_account = intersight.IamAccountApi(api_instance)
    get_account = check_account.iam_accounts_get()
    if check_account.api_client.last_response.status != 200:
      print("The Intersight API and Account Availability Test did not pass.")
      print("The Intersight account information could not be verified.")
      print("Exiting due to the Intersight account being unavailable.\n")
      sys.exit(0)
    else:
      account_name = get_account.results[0].name
      print("The Intersight API and Account Availability Test has passed.\n")
      print("The account named '" + account_name + "' has been found.\n")
  except Exception:
    print("Unable to access the Intersight API.")
    print("Exiting due to the Intersight API being unavailable.\n")
    sys.exit(0)


# Run the Intersight API and Account Availability Test
print("Running the Intersight API and Account Availability Test.")
test_intersight_service()

# Delete all profiles, policies, objects, etc. within the listed Intersight API types
print("Running the Intersight Account Reset process.\n")

# Identify API key owner for automatic exemption
try:
  key_id_split = key_id.split("/")
  api_key_owner = key_id_split[1]
except Exception as exception_message:
  print("There was an issue identifying the API key owner. Please review the exception message.")
  print(exception_message)

# Remove unexempted user accounts
print("Searching for and removing any users found that are not exempted.")
print("Retrieving all associated users.")
get_users = iu_get("iam/Users")
for user in get_users["Results"]:
  if user["Moid"] == api_key_owner:
    print("The user named " + user["Email"] + " has been identified as the API key owner and will be automatically exempted from removal.")
  elif user["Email"] not in exempt_users:
    print("Attempting to remove the user named " + user["Email"] + " at URL: " + base_url + "/iam/Users/" + user["Moid"])
    delete_users = iu_delete_moid("iam/Users",user["Moid"])
    if delete_users == "The DELETE method failed.":
      print("The removal of the account named " + user["Email"] + " was unsuccessful. Please manually review the Intersight account if necessary.")
    else:
      print("The account " + user["Email"] + " has been successfully removed.")
  else:
    print("The user named " + user["Email"] + " has been identified as part of the exemption list, no further action needed.")

print("\nThe process of searching for and removing any unexempted users is complete.\n")

# List of Intersight profile API types for cleanup run, based on API Reference Version v1.0.9-2440
intersight_profile_apis = [
  {"name": "HyperFlex Cluster Profiles",
   "path": "hyperflex/ClusterProfiles",
   },
  {"name": "Server Profiles",
   "path": "server/Profiles",
   },
  {"name": "Recovery Backup Profiles",
   "path": "recovery/BackupProfiles",
   },
  ]

# Check for and delete any Intersight profiles
print("Beginning cleanup of any Intersight profiles...\n")
for profile_api in intersight_profile_apis:
  print(f'Searching for and deleting any Intersight {profile_api["name"]}.')

  # Retrieve all available profiles
  get_profiles = iu_get(profile_api["path"])

  if get_profiles is not None:
    if get_profiles["Results"] is None:
      print(f'There are no {profile_api["name"]} available to delete.\n')
    else:
      for current_profile in get_profiles["Results"]:
        # Abort any current profiles in a deployment state
        print(f'The profile named {current_profile["Name"]} has been identified.')
        print(f'Attempting to abort any incomplete states of {current_profile["Name"]} if needed.')
        profile_abort_patch_data = {"Action": "Abort"}
        abort_profile = iu_patch_moid(profile_api["path"],current_profile["Moid"],profile_abort_patch_data)
        if abort_profile == "The PATCH method failed.":
          print(f'Unable to abort the state of {current_profile["Name"]}, the action may not be needed. Check to see if the attempt to delete the profile is successful below.')
        else:
          print(f'The abort action was successful on {current_profile["Name"]}.')
        print(f'Attempting to unassign the profile named {current_profile["Name"]} if needed.')
        profile_unassign_patch_data = {"Action": "Unassign"}
        unassign_profile = iu_patch_moid(profile_api["path"],current_profile["Moid"],profile_unassign_patch_data)
        if unassign_profile == "The PATCH method failed.":
          print(f'Unable to unassign {current_profile["Name"]}, the action may not be needed. Check to see if the attempt to delete the profile is successful below.')
        else:
          print(f'The unassign action was successful on {current_profile["Name"]}.')
        print(f'Attempting to delete the profile named {current_profile["Name"]} at URL: {base_url}/{profile_api["path"]}/{current_profile["Moid"]}')
        delete_profile = iu_delete_moid(profile_api["path"],current_profile["Moid"])
        if delete_profile == "The DELETE method failed.":
          print(f'Unable to delete the profile named {current_profile["Name"]}, please manually review the status.')
        else:
          print(f'The profile named {current_profile["Name"]} has been successfully deleted.')

  # If the profile API type is unaccessible, log status and move on
  else:
    print(f'The API type for {profile_api["name"]} is unavailable.')
  print(f'\nThe process of searching for and deleting any {profile_api["name"]} is complete.\n')

# List of general Intersight API types for first cleanup run, based on API Reference v1.0.9-2440
general_intersight_apis = [
    {"name": "BIOS Policies",
     "path": "bios/Policies",
     },
    {"name": "Boot Precision Policies",
     "path": "boot/PrecisionPolicies",
     },
    {"name": "Device Connector Policies",
     "path": "deviceconnector/Policies",
     },
    {"name": "Firmware Upgrades",
     "path": "firmware/Upgrades",
     },
    {"name": "HyperFlex Auto Support Policies",
     "path": "hyperflex/AutoSupportPolicies",
     },
    {"name": "HyperFlex Cluster Network Policies",
     "path": "hyperflex/ClusterNetworkPolicies",
     },
    {"name": "HyperFlex Cluster Storage Policies",
     "path": "hyperflex/ClusterStoragePolicies",
     },
    {"name": "HyperFlex External Fibre Channel Storage Policies",
     "path": "hyperflex/ExtFcStoragePolicies",
     },
    {"name": "HyperFlex External iSCSI Storage Policies",
     "path": "hyperflex/ExtIscsiStoragePolicies",
     },
    {"name": "HyperFlex End User Feature Limits",
     "path": "hyperflex/FeatureLimitExternals",
     },
    {"name": "HyperFlex Local Credential Policies",
     "path": "hyperflex/LocalCredentialPolicies",
     },
    {"name": "HyperFlex Node Configuration Policies",
     "path": "hyperflex/NodeConfigPolicies",
     },
    {"name": "HyperFlex Node Profiles",
     "path": "hyperflex/NodeProfiles",
     },
    {"name": "HyperFlex Proxy Setting Policies",
     "path": "hyperflex/ProxySettingPolicies",
     },
    {"name": "HyperFlex Software Version Policies",
     "path": "hyperflex/SoftwareVersionPolicies",
     },
    {"name": "HyperFlex System Configuration Policies",
     "path": "hyperflex/SysConfigPolicies",
     },
    {"name": "HyperFlex UCSM Configuration Policies",
     "path": "hyperflex/UcsmConfigPolicies",
     },
    {"name": "HyperFlex vCenter Configuration Policies",
     "path": "hyperflex/VcenterConfigPolicies",
     },
    {"name": "End Point Users",
     "path": "iam/EndPointUsers",
     },
    {"name": "End Point User Policies",
     "path": "iam/EndPointUserPolicies",
     },
    {"name": "End Point User Roles",
     "path": "iam/EndPointUserRoles",
     },
    {"name": "LDAP Groups",
     "path": "iam/LdapGroups",
     },
    {"name": "LDAP Policies",
     "path": "iam/LdapPolicies",
     },
    {"name": "LDAP Providers",
     "path": "iam/LdapProviders",
     },
    {"name": "Qualifiers",
     "path": "iam/Qualifiers",
     },
    {"name": "User Groups",
     "path": "iam/UserGroups",
     },
    {"name": "IPMI Over LAN Policies",
     "path": "ipmioverlan/Policies",
     },
    {"name": "KVM Policies",
     "path": "kvm/Policies",
     },
    {"name": "Network Configuration Policies",
     "path": "networkconfig/Policies",
     },
    {"name": "NTP Policies",
     "path": "ntp/Policies",
     },
    {"name": "SD Card Policies",
     "path": "sdcard/Policies",
     },
    {"name": "SMTP Policies",
     "path": "smtp/Policies",
     },
    {"name": "SNMP Policies",
     "path": "snmp/Policies",
     },
    {"name": "Serial Over LAN Policies",
     "path": "sol/Policies",
     },
    {"name": "SSH Policies",
     "path": "ssh/Policies",
     },
    {"name": "Storage Disk Group Policies (RAID, JBOD, Unconfigured Good, Etc.)",
     "path": "storage/DiskGroupPolicies",
     },
    {"name": "Syslog Policies",
     "path": "syslog/Policies",
     },
    {"name": "vMedia Policies",
     "path": "vmedia/Policies",
     },
    {"name": "Oauth Users",
     "path": "oauth/OauthUsers",
     },
    {"name": "REST Resources Groups",
     "path": "resource/Groups",
     },
    {"name": "Test Crypt Credentials",
     "path": "testcrypt/Credentials",
     },
    {"name": "Test Crypt Read Only Users",
     "path": "testcrypt/ReadOnlyUsers",
     },
    {"name": "Cisco Validated Design (CVD) Deployment Tasks",
     "path": "cvd/DeploymentTasks",
     },
    {"name": "Cisco Validated Design (CVD) Templates",
     "path": "cvd/Templates",
     },
    {"name": "Validation Tasks",
     "path": "cvd/ValidationTasks",
     },
    {"name": "VIC Adapter Configuration Policies",
     "path": "adapter/ConfigPolicies",
     },
    {"name": "Intersight Appliance Backups",
     "path": "appliance/Backups",
     },
    {"name": "Intersight Appliance Restores",
     "path": "appliance/Restores",
     },
    {"name": "Trusted Source Certificates",
     "path": "iam/TrustPoints",
     },
    {"name": "Operating System Images",
     "path": "softwarerepository/OperatingSystemFiles",
     },
    {"name": "Storage Policies",
     "path": "storage/StoragePolicies",
     },
    {"name": "Ethernet Adapter Policies",
     "path": "vnic/EthAdapterPolicies",
     },
    {"name": "Virtual Ethernet Interfaces",
     "path": "vnic/EthIfs",
     },
    {"name": "Ethernet Network Policies",
     "path": "vnic/EthNetworkPolicies",
     },
    {"name": "Ethernet QoS Policies",
     "path": "vnic/EthQosPolicies",
     },
    {"name": "Fibre Channel Adapter Policies",
     "path": "vnic/FcAdapterPolicies",
     },
    {"name": "Virtual Fibre Channel Interfaces",
     "path": "vnic/FcIfs",
     },
    {"name": "Fibre Channel Network Policies",
     "path": "vnic/FcNetworkPolicies",
     },
    {"name": "Fibre Channel QoS Policies",
     "path": "vnic/FcQosPolicies",
     },
    {"name": "LAN Connectivity Policies",
     "path": "vnic/LanConnectivityPolicies",
     },
    {"name": "SAN Connectivity Policies",
     "path": "vnic/SanConnectivityPolicies",
     },
    {"name": "HyperFlex Cluster Upgrade Initiations",
     "path": "hyperflex/InitiateHxClusterUpgrades",
     },
    {"name": "HyperFlex Software Version Policies",
     "path": "hyperflex/SoftwareVersionPolicies",
     },
    {"name": "UCS Director Accounts",
     "path": "iaas/UcsdInfos",
     },
    {"name": "CIMC Server Management Access Policies",
     "path": "access/Policies",
     },
    {"name": "Intersight Assist Managed Devices",
     "path": "asset/ManagedDevices",
     },
    {"name": "Asset Targets",
     "path": "asset/Targets",
     },
    {"name": "Adaptor Descriptors",
     "path": "capability/AdapterUnitDescriptors",
     },
    {"name": "Chassis Enclosure Descriptors",
     "path": "capability/ChassisDescriptors",
     },
    {"name": "Chassis Enclosure Manufacturing Properties",
     "path": "capability/ChassisManufacturingDefs",
     },
    {"name": "Switch Equipment Physical Properties",
     "path": "capability/EquipmentPhysicalDefs",
     },
    {"name": "Switch Equipment Slot Arrays",
     "path": "capability/EquipmentSlotArrays",
     },
    {"name": "Fan Module Descriptors",
     "path": "capability/FanModuleDescriptors",
     },
    {"name": "Fan Module Manufacturing Properties",
     "path": "capability/FanModuleManufacturingDefs",
     },
    {"name": "IO Module Capabilities",
     "path": "capability/IoCardCapabilityDefs",
     },
    {"name": "IO Module Descriptors",
     "path": "capability/IoCardDescriptors",
     },
    {"name": "IO Module Manufacturing Properties",
     "path": "capability/IoCardManufacturingDefs",
     },
    {"name": "IO Module Port Group Aggregation Capabilities",
     "path": "capability/PortGroupAggregationDefs",
     },
    {"name": "Power Supply Unit Descriptors",
     "path": "capability/PsuDescriptors",
     },
    {"name": "Power Supply Unit Manufacturing Properties",
     "path": "capability/PsuManufacturingDefs",
     },
    {"name": "SIOC Module Capabilities",
     "path": "capability/SiocModuleCapabilityDefs",
     },
    {"name": "SIOC Module Descriptors",
     "path": "capability/SiocModuleDescriptors",
     },
    {"name": "SIOC Module Manufacturing Properties",
     "path": "capability/SiocModuleManufacturingDefs",
     },
    {"name": "Switch Equipment Capabilities",
     "path": "capability/SwitchCapabilities",
     },
    {"name": "Switch Equipment Descriptors",
     "path": "capability/SwitchDescriptors",
     },
    {"name": "Switch Equipment Manufacturing Properties",
     "path": "capability/SwitchManufacturingDefs",
     },
    {"name": "Blade Server Identities",
     "path": "compute/BladeIdentities",
     },
    {"name": "Rack Server Identities",
     "path": "compute/RackUnitIdentities",
     },
    {"name": "Export Operations (aka Exporter Instances)",
     "path": "config/Exporters",
     },
    {"name": "Import Operations (aka Importer Instances)",
     "path": "config/Importers",
     },
    {"name": "Connector Pack Installs and Upgrades",
     "path": "connectorpack/ConnectorPackUpgrades",
     },
    {"name": "Ethernet Network Control Policies",
     "path": "fabric/EthNetworkControlPolicies",
     },
    {"name": "Ethernet Network Group Policies",
     "path": "fabric/EthNetworkGroupPolicies",
     },
    {"name": "Ethernet Network Policies",
     "path": "fabric/EthNetworkPolicies",
     },
    {"name": "Fibre Channel Network Policies",
     "path": "fabric/FcNetworkPolicies",
     },
    {"name": "Fibre Channel Uplink Port Channel Roles",
     "path": "fabric/FcUplinkPcRoles",
     },
    {"name": "Fibre Channel Uplink Roles",
     "path": "fabric/FcUplinkRoles",
     },
    {"name": "FCoE Uplink Port Channel Roles",
     "path": "fabric/FcoeUplinkPcRoles",
     },
    {"name": "FCoE Uplink Roles",
     "path": "fabric/FcoeUplinkRoles",
     },
    {"name": "Multicast Policies",
     "path": "fabric/MulticastPolicies",
     },
    {"name": "Port Channel Operations",
     "path": "fabric/PcOperations",
     },
    {"name": "Port Modes",
     "path": "fabric/PortModes",
     },
    {"name": "Port Operations",
     "path": "fabric/PortOperations",
     },
    {"name": "Port Policies",
     "path": "fabric/PortPolicies",
     },
    {"name": "Server Port Roles",
     "path": "fabric/ServerRoles",
     },
    {"name": "Switch Cluster Profiles",
     "path": "fabric/SwitchClusterProfiles",
     },
    {"name": "Switch Profiles",
     "path": "fabric/SwitchProfiles",
     },
    {"name": "System QoS Policies",
     "path": "fabric/SystemQosPolicies",
     },
    {"name": "Uplink Port Channel Roles",
     "path": "fabric/UplinkPcRoles",
     },
    {"name": "Uplink Roles",
     "path": "fabric/UplinkRoles",
     },
    {"name": "VLANs",
     "path": "fabric/Vlans",
     },
    {"name": "VSANs",
     "path": "fabric/Vsans",
     },
    {"name": "Fibre Channel WWN Pools",
     "path": "fcpool/Pools",
     },
    {"name": "BIOS Descriptors",
     "path": "firmware/BiosDescriptors",
     },
    {"name": "Board Controller Descriptors",
     "path": "firmware/BoardControllerDescriptors",
     },
    {"name": "Chassis Firmware Upgrades",
     "path": "firmware/ChassisUpgrades",
     },
    {"name": "CIMC Descriptors",
     "path": "firmware/CimcDescriptors",
     },
    {"name": "DIMM Descriptors",
     "path": "firmware/DimmDescriptors",
     },
    {"name": "Drive Descriptors",
     "path": "firmware/DriveDescriptors",
     },
    {"name": "GPU Descriptors",
     "path": "firmware/GpuDescriptors",
     },
    {"name": "HBA Descriptors",
     "path": "firmware/HbaDescriptors",
     },
    {"name": "IOM Descriptors",
     "path": "firmware/IomDescriptors",
     },
    {"name": "mSwitch Descriptors",
     "path": "firmware/MswitchDescriptors",
     },
    {"name": "NXOS (Fabric Interconnects) Descriptors",
     "path": "firmware/NxosDescriptors",
     },
    {"name": "PCIE Descriptors",
     "path": "firmware/PcieDescriptors",
     },
    {"name": "Power Supply Unit Descriptors",
     "path": "firmware/PsuDescriptors",
     },
    {"name": "SAS Expander Descriptors",
     "path": "firmware/SasExpanderDescriptors",
     },
    {"name": "Storage Controller Descriptors",
     "path": "firmware/StorageControllerDescriptors",
     },
    {"name": "Switch Firmware Upgrades",
     "path": "firmware/SwitchUpgrades",
     },
    {"name": "HXAP Data Center Objects",
     "path": "hyperflex/HxapDatacenters",
     },
    {"name": "OAuth2 Client Application Registrations",
     "path": "iam/AppRegistrations",
     },
    {"name": "Certificate Signing Requests (CSR)",
     "path": "iam/CertificateRequests",
     },
    {"name": "Certificates",
     "path": "iam/Certificates",
     },
    {"name": "Access Management IP Addresses",
     "path": "iam/IpAddresses",
     },
    {"name": "User OAuth Tokens",
     "path": "iam/OAuthTokens",
     },
    {"name": "User and User Group Role Permissions",
     "path": "iam/Permissions",
     },
    {"name": "Private Key Specifications",
     "path": "iam/PrivateKeySpecs",
     },
    {"name": "Resource Roles",
     "path": "iam/ResourceRoles",
     },
    {"name": "Intelligent Platform Management Interface (IPMI) Over LAN Policies",
     "path": "ipmioverlan/Policies",
     },
    {"name": "IP Pools",
     "path": "ippool/Pools",
     },
    {"name": "MAC Address Pools",
     "path": "macpool/Pools",
     },
    {"name": "Persistent Memory Policies",
     "path": "memory/PersistentMemoryPolicies",
     },
    {"name": "Multi-Tenancy Organizations",
     "path": "organization/Organizations",
     },
    {"name": "OS Installation Answer Files",
     "path": "os/ConfigurationFiles",
     },
    {"name": "Backup Configuration Policies",
     "path": "recovery/BackupConfigPolicies",
     },
    {"name": "On Demand Backups",
     "path": "recovery/OnDemandBackups",
     },
    {"name": "Restore Operations",
     "path": "recovery/Restores",
     },
    {"name": "Recovery Schedule Configuration Policies",
     "path": "recovery/ScheduleConfigPolicies",
     },
]

# Pre-set list for general Intersight API types that may be marked for a second cleanup run
retry_general_intersight_apis = []

# Begin first cleanup run of general API types
print("Beginning first cleanup run of general API types...\n")
for api in general_intersight_apis:
  print("Searching for and deleting any Intersight objects under API type: " + api["name"] + ".")

  # Check each API type for available objects
  first_cleanup_run = iu_get(api["path"])

  # If the API type is accessible, check for objects and attempt to delete
  if first_cleanup_run is not None:
    if first_cleanup_run["Results"] is None:
      print("There are no objects available to delete.\n")
    else:
      for resource in first_cleanup_run["Results"]:
        print("Attempting to delete the object type: " + resource["ObjectType"] + " at URL: " + base_url + "/" + api["path"] + "/" + resource["Moid"])
        delete_object = iu_delete_moid(api["path"],resource["Moid"])
        if delete_object == "The DELETE method failed.":
          print("Unable to delete the object type: " + resource["ObjectType"] + ", another attempt will be made on the second cleanup run.")
          if api not in retry_general_intersight_apis:
            print('Marking the API type: "' + api["name"] + '" for a second cleanup run.\n')
            retry_general_intersight_apis.append(api)
        else:
          print("The " + resource["ObjectType"] + " object instance has been successfully deleted.\n")

  # If the API type is unaccessible, mark for a second cleanup run, log and move on
  else:
    print('The API type "' + api["name"] + '" is unavailable. Another attempt to access it will be made on the second cleanup run.')
    if api not in retry_general_intersight_apis:
      print('Marking the API type: "' + api["name"] + '" for a second cleanup run.\n')
      retry_general_intersight_apis.append(api)

# Begin the second cleanup run of general API types
print("Beginning the second cleanup run of general API types...\n")
for api2 in retry_general_intersight_apis:
  print("Searching for and deleting any Intersight objects under API type: " + api2["name"] + ".")

  # Check each API type for available objects
  second_cleanup_run = iu_get(api2["path"])
  
  # If the API type is accessible, check for objects and attempt to delete
  if second_cleanup_run is not None:
    if second_cleanup_run["Results"] is None:
      print("There are no objects available to delete.\n")
    else:
      for resource2 in second_cleanup_run["Results"]:
        print("Attempting to delete the object type: " + resource2["ObjectType"] + " at URL: " + base_url + "/" + api2["path"] + "/" + resource2["Moid"])
        delete_object2 = iu_delete_moid(api2["path"],resource2["Moid"])
        if delete_object2 == "The DELETE method failed.":
          print("Unable to delete the object type: " + resource2["ObjectType"] + " on the second try, please manually review the Intersight account if necessary.\n")
        else:
          print("The " + resource2["ObjectType"] + " object instance has been successfully deleted.\n")

  # If the API type is unaccessible, log and move on
  else:
    print('The API type "' + api2["name"] + '" is unavailable. Please manually review the Intersight account if necessary.\n')

print("The process of searching for and deleting any Intersight objects under general API types is complete.\n")

# Delete any registered devices except those exempted

# Retrieve all currently registered devices
print("Searching for and removing any registered devices except those exempted.")
devices = iu_get("asset/DeviceRegistrations")

# Extract any unexempted devices from the results and attempt to unregister
if devices["Results"] is not None:
    for device in devices["Results"]:
      for hostname in device["DeviceHostname"]:
        device_hostname = hostname
      for pid in device["Pid"]:
        device_pid = pid
      for serial in device["Serial"]:
        device_serial = serial
      if any(attribute in exempt_devices for attribute in (device_hostname, device_pid, device_serial)):
        print("The claimed device named " + device_hostname + " has been identified as part of the exemption list, no further action needed.")
      else:
          claim = device.get("DeviceClaim")
          claim_moid = claim["Moid"]
          print("Attempting to unclaim the device named " + device_hostname + " at URL: " + base_url + "/asset/DeviceRegistrations/" + device["Moid"])
          unclaim_device = iu_delete_moid("asset/DeviceClaims",claim_moid)
          if unclaim_device == "The DELETE method failed.":
            print("Unable to unclaim the device named " + device_hostname + ". Please manually unclaim the device from the Intersight account.")
          else:
            print("The device named " + device_hostname + " has been succesfully unclaimed.")

print("\nThe process of searching for and removing any unexempted registered devices is complete.\n")
  
# Account cleanup and reset complete
print("The Intersight Account Reset process is complete.\n")

# Ending the Cisco Intersight Account Reset Tool
print("The Cisco Intersight Account Reset Tool has completed.\n")

sys.exit(0)
