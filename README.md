[![Gitter chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/AMP-for-Endpoints "Gitter chat")

### AMP for Endpoints Add SHA256(s) to Simple Custom Detection List:

Script takes either a SHA256 or File (one SHA256 per line) as a command line argument. If neither is provided it will prompt the user to enter a SHA256 or file. It validates the provided input and prompts the user for which Simple Custom Detection (SCD) List to add SHA256s to and queries the SCD List for existing list items. The user provided SHA256s are compared against the existing list items and any duplicates are removed. The disposition for remaining SHA256s are looked up using Threat Response's /deliberate/observables endpoint. Malicious SHA256s are removed from the remaining list of user provided SHA256s. The user is prompted to add the SHA256s to the SCD List, if the users says response y the SHA256s are then added to the SCD List


### Before using you must update the following:
- amp_client_id
- amp_client_password
- amp_hostname
- tr_client_id
- tr_client_password

Install required Python modules using:
```
pip install -U -r requirements.txt
```

### Usage:
```
python add_sha256_to_scd.py
```
or
```
python add_sha256_to_scd.py hashes.txt
```
or
```
python add_sha256_to_scd.py fe306a19405b7480b14c913d804db4c8fa8f37fc75d8765210a9a839ec5d8124
```

### Example script output:  
```
Validating provided input
  Valid SHA256s: 6
  Items that are not SHA256s: 2

Getting SCD Lists
1 - Simple Custom Detection List
2 - PDFs
3 - Binaries
Enter the index of the SCD List you would like to add SHA256s to: 3

Getting SHA256s for: Binaries
  Page: 1 of 1
SHA256s on Binaries: 1

Checking valid SHA256s against existing SHA256s on: Binaries
  Number that already exist: 1
  Number that can be added: 5

Checking verdicts to remove any known malicious SHA256s
  Checking verdicts for chunk 1 of 1
Number of provided SHA256s with a malicious disposition: 2

Do you want to add 3 SHA256(s) to Binaries? (y/n): y
Adding f4ea1dc505718a14325f4cabcc45348ee89ad510498424f21f261883314b950b - DONE!
Adding fa1c94915329d25a0c43187e2ea503b762c8e3fea67d09b34b2433e56fd20c6a - DONE!
Adding fc74bb02307458f0b7f8e62d50a36c0e88c5f42959afdf664a08c335e3d68318 - DONE!
```
