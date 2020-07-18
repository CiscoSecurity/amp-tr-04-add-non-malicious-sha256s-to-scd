import re
import os
import sys
import math
from datetime import datetime

import requests
from threatresponse import ThreatResponse

def clear_input(message=None):
    '''Clear the last line from the terminal and output a message
    '''
    sys.stdout.write('\x1b[1A')
    sys.stdout.write('\x1b[2K')
    sys.stdout.write(message)

def confirm_continue(message):
    '''Ask the user if they want to continue
       Keep asking until the input starts with  'y', 'Y', 'n', or 'N'
    '''
    while True:
        reply = str(input(f'{message}')).lower().strip()
        if reply[:1] == 'y': # using [:1] instead of [0] prevents IndexError if the reply is empty
            return True
        if reply[:1] == 'n':
            return False
        clear_input(f'{reply} is not \"y\" or \"n\".')

def split_list(list_to_split, max_size=20):
    '''Split a large list into a list of lists with a maximum size of 20 items
    This is used to lighten the load on the Threat Response API by limiting the
    number of itmes in a single query to 20 instead of potentially thousands
    '''
    return [list_to_split[i:i + max_size] for i in range(0, len(list_to_split), max_size)]

def ask_for_scd_index(count):
    '''Ask the user for a SCD index
       Keep asking until they enter a valid SCD index
    '''
    while True:
        try:
            reply = (input('Enter the index of the SCD List you would like to add SHA256s to: '))
            index = int(reply)
            if 0 < index <= count:
                return index-1
            clear_input(f'{reply} is not a valid index try again.\n')
        except ValueError:
            clear_input(f'{reply} is not a number.\n')

def validate_input():
    '''Validate the user provided a command line argument is a SHA256 of File
    If no command line argument was provided prompt the user to enter a SHA256 of File
    Validate the provided input is a SHA256 or File and return the input and type
    '''
    try:
        user_input = sys.argv[1]
        input_type = validate_file_or_sha256(user_input)
        if not input_type:
            print(f'Provided argument {user_input} is not a valid SHA256 or File.')
            user_input, input_type = ask_for_sha256_or_file()
    except IndexError:
        user_input, input_type = ask_for_sha256_or_file()

    return user_input, input_type

def ask_for_sha256_or_file():
    '''Ask for SHA256 of File
    '''
    while True:
        reply = str(input('Enter a SHA256 or path to a File: ')).strip()
        input_type = validate_file_or_sha256(reply)
        if input_type:
            print() # New line so "Getting SCD Lists" is printed in its own section
            return reply, input_type
        clear_input(f'{reply} is not a valid SHA256 or File.\n')

def validate_file_or_sha256(string):
    '''Check if the provided string is an File or a SHA256
    '''
    if validate_file(string):
        return 'File'
    if validate_sha256(string):
        return 'SHA256'
    return False

def validate_sha256(string):
    '''Validate the SHA256
    '''
    match_obj = re.match(r"[a-fA-F0-9]{64}$", string)
    return bool(match_obj)

def validate_file(string):
    '''Validate the provided string is a file
    '''
    return os.path.isfile(string)

def get_scd_file_lists(session, amp_hostname):
    '''Query AMP for Endpoints for SCD Lists
    '''
    url = f'https://{amp_hostname}/v1/file_lists/simple_custom_detections'
    response = session.get(url)
    return response

def get_file_list_items(session, amp_hostname, file_list_guid):
    '''Get File List items for a given SCD GUID
    Paginate through the results when there are more than 500 items returned
    '''
    def query_api(url):
        '''Query the AMP for Endpoints AMP for the provided URL
        Return the decoded JSON response
        '''
        response = session.get(url)
        response_json = response.json()
        return response_json

    def parse_response(response_json):
        '''Parse the AMP for Endpoints response
        Store the SCD List items in the response container
        '''
        items = response_json.get('data', {}).get('items', [])
        response_items.extend(items)

    # Set the page count to 1
    page_count = 1

    # Container to store the SCD List items
    response_items = []

    print(f'  Page: {page_count} of', end=' ')
    url = f'https://{amp_hostname}/v1/file_lists/{file_list_guid}/files'

    # Query AMP for Endpoints for SCD List items and decode the JSON response
    response_json = query_api(url)

    # Name total and items_per_page from the response
    total = response_json.get('metadata', {}).get('results', {}).get('total')
    items_per_page = response_json.get('metadata', {}).get('results', {}).get('items_per_page')

    # Calculate total number of pages
    pages = math.ceil(total/items_per_page)

    # If pages is 0 because total is 0 set pages to 1
    if not pages:
        pages = 1

    print(pages)

    # Parse AMP for Endpoints response
    parse_response(response_json)

    # Get the next page of results if needed
    while 'next' in response_json['metadata']['links']:
        page_count += 1
        print(f'  Page: {page_count} of {pages}')
        next_url = response_json['metadata']['links']['next']

        # Query AMP for Endpoints for the next page of SCD List items
        response_json = query_api(next_url)

        # Parse AMP for Endpoints response
        parse_response(response_json)

    return response_items

def compare_list_items(scd_name, existing_list_items, validated_user_provided_hashes):
    '''Compare user provided hashes agaist the selected SCD List
    Return only the hashes that are not already on the SCD List
    '''
    if existing_list_items:
        print(f'\nChecking valid SHA256s against existing SHA256s on: {scd_name}')
        existing_user_provided_hashes = validated_user_provided_hashes.intersection(existing_list_items)
        new_user_provided_hashes = validated_user_provided_hashes.difference(existing_list_items)

        if existing_user_provided_hashes:
            print(f'  Number that already exist: {len(existing_user_provided_hashes)}')
        if new_user_provided_hashes:
            print(f'  Number that can be added: {len(new_user_provided_hashes)}')
        return new_user_provided_hashes
    return validated_user_provided_hashes

def add_list_item(session, amp_hostname, file_list_guid, sha256):
    '''Remove SHA256 from SCD
    '''
    url = f'https://{amp_hostname}/v1/file_lists/{file_list_guid}/files/{sha256}'
    response = session.post(url)
    return response

def get_verdicts(client, payload):
    '''Query Threat Response for Verdicts of SHA256s
    '''
    response = client.enrich.deliberate.observables(payload)
    return response

def parse_verdicts(response, malicious_hashes):
    '''Parse the Threat Response response check the AMP File Reputation for malicious dispositions
    '''
    data = response.get('data', [])

    # Iterate over returned data from each module
    for module in data:
        module_type_id = module.get('module_type_id')

        # Look for the AMP File Reputation module type
        if module_type_id == '1898d0e8-45f7-550d-8ab5-915f064426dd':
            verdicts = module.get('data', []).get('verdicts', {})
            docs = verdicts.get('docs', [])

            # Iterate over documents returned by the AMP File Reputation module
            for doc in docs:
                disposition = doc.get('disposition')
                observable = doc.get('observable', {}).get('value')
                if disposition == 2:
                    malicious_hashes.add(observable)

def replace_space(string):
    '''Replace spaces in a string with underscore
    '''
    return string.replace(' ', '_')

def validate_file_contents(user_input):
    '''Read the contents of the user provided file
    Validate which lines are SHA256s and which lines are not, store and return both
    '''
    # Read the provided file to a set
    user_provided_hashes = read_file(user_input)

    # Containers for valid SHA256s and items that are not SHA256s
    validated_user_provided_hashes = set()
    invalid_user_provided_hashes = set()

    # Iterate over user provided hashes and validate them
    print('Validating provided input')
    for item in user_provided_hashes:
        if validate_sha256(item):
            validated_user_provided_hashes.add(item)
        else:
            invalid_user_provided_hashes.add(item)
    # Exit if there are no valid SHA256s
    if not validated_user_provided_hashes:
        sys.exit(
            f'\nNone of the {len(user_provided_hashes)} items provided are valid SHA256s.'
            f'\nCheck the contents of {user_input} and try again.'
        )

    # Inform how many provided items are valid SHA256s and how many are not if any
    print(f'  Valid SHA256s: {len(validated_user_provided_hashes)}')

    if invalid_user_provided_hashes:
        print(f'  Items that are not SHA256s: {len(invalid_user_provided_hashes)}')

    return validated_user_provided_hashes, invalid_user_provided_hashes

def read_file(file_name):
    '''Read user provided file to set
    '''
    with open(file_name, 'r') as file:
        new_list_items = set(file.read().splitlines())
    return new_list_items

def save_list_items(file_name, malicious_hashes):
    '''Write SHA256s that have malicious disposition to file
    '''
    with open(file_name, 'w') as file:
        for sha256 in malicious_hashes:
            file.write(f'{sha256}\n')

def main():
    '''Main script logic
    '''

    # Calculate now timestamp and store as file system friendly string
    now = datetime.now()
    start_time = datetime.strftime(now, '%Y-%m-%dT%H.%M.%S.%f')

    # Validate a SHA256 or file was provided
    user_input, input_type = validate_input()

    # AMP for Endpoints API Credentials
    amp_client_id = 'a1b2c3d4e5f6g7h8i9j0'
    amp_client_password = 'a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6'
    amp_hostname = 'api.amp.cisco.com'

    # Instantiate AMP for Endpoints Session
    amp_session = requests.Session()
    amp_session.auth = (amp_client_id, amp_client_password)

    # Threat Response API Credentials
    tr_client_id = 'client-asdf12-34as-df12-34as-df1234asdf12'
    tr_client_password = 'asdf1234asdf1234asdf1234asdf1234asdf1234asdf1234asdf12'

    # Instantiate Threat Response Client
    client = ThreatResponse(
        client_id=tr_client_id,
        client_password=tr_client_password,
    )

    # Container to store SHA256s that have malicious disposition in AMP cloud
    malicious_hashes = set()

    if input_type == 'File':
        # Validate and store user provided hashes in a set
        validated_user_provided_hashes, invalid_user_provided_hashes = validate_file_contents(user_input)
        print() # New line so "Getting SCD Lists" is printed in its own section
    else:
        # Store the user provided SHA256
        validated_user_provided_hashes = {user_input}

    # Get Simple Custom Detaction File Lists
    print('Getting SCD Lists')
    scd_lists = get_scd_file_lists(amp_session, amp_hostname).json()
    data = scd_lists.get('data', [])

    # Present SCD Lists to user and ask which one to use
    for index, scd in enumerate(data, start=1):
        print(f'{index} - {scd["name"]}')
    index = ask_for_scd_index(len(data))

    # Name SCD Name and GUID
    scd_name = data[index]['name']
    scd_guid = data[index]['guid']

    # Query AMP for Endpoints to get list items for selected SCD List
    print(f'\nGetting SHA256s for: {scd_name}')
    scd_list_items = get_file_list_items(amp_session, amp_hostname, scd_guid)

    # Put the SHA256s from the SCD List into a set using set comprehension
    existing_list_items = {list_item.get("sha256") for list_item in scd_list_items}

    # Inform how many SCD List items were found
    print(f'SHA256s on {scd_name}: {len(existing_list_items)}')

    # Compare user provided hashes against the slected SCD List
    new_user_provided_hashes = compare_list_items(
        scd_name, existing_list_items, validated_user_provided_hashes
    )

    if not new_user_provided_hashes:
        sys.exit(f'\nAll of the provided SHA256s are already on {scd_name}\nBye!')

    # Build Threat Response Enrich Payloads using list comprehension
    enrich_payloads = [{"value": sha256, "type": "sha256"} for sha256 in new_user_provided_hashes]

    # Split payloads into list of lists with 20 items maximum
    item_count = len(enrich_payloads)
    if item_count > 20:
        print(f'\nSplitting into {math.ceil(item_count/20)} chunks of 20 or less and checking verdicts')
    else:
        print('\nChecking verdicts to remove any known malicious SHA256s')
    chunked_enrich_payloads = split_list(enrich_payloads)

    # Iterate over list and get Verdicts for list of SCD List items
    for payload_index, payload in enumerate(chunked_enrich_payloads, start=1):

        # Query Threat Response for verdcits
        print(f'  Checking verdicts for chunk {payload_index} of {len(chunked_enrich_payloads)}')
        verdicts = get_verdicts(client, payload)
        parse_verdicts(verdicts, malicious_hashes)

    # Inform how many malicious dispositions were returned
    print(f'Number of provided SHA256s with a malicious disposition: {len(malicious_hashes)}')

    non_malicious_user_provided_hashes = new_user_provided_hashes.difference(malicious_hashes)

    if not non_malicious_user_provided_hashes:
        sys.exit('\nProvided SHA256s are already malicious in the AMP File Reputation Database\nBye!')

    if not confirm_continue(
            f'\nDo you want to add {len(non_malicious_user_provided_hashes)}'
            f' SHA256(s) to {scd_name}? (y/n): '
    ):
        sys.exit("Bye!")

    # Iterate over remaining SHA256(s) and add to selected SCD List
    for sha256 in non_malicious_user_provided_hashes:
        print(f'Adding {sha256}', end=' ')
        response = add_list_item(amp_session, amp_hostname, scd_guid, sha256)
        if response.ok:
            print('- DONE!')
        else:
            print('- SOMETHING WENT WRONG!')

if __name__ == '__main__':
    main()
