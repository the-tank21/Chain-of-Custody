#!/usr/bin/env python3
# Main file for project 1

import argparse
import struct 
import hashlib
from Crypto.Cipher import AES
import time
from datetime import datetime
import os
import uuid

AES_KEY = b"R0chLi4uLi4uLi4=" # key from project document
cipher = AES.new(AES_KEY, AES.MODE_ECB)
# Profile passwords
PASSWORDS = {
    "POLICE": "P80P",
    "LAWYER": "L76L",
    "ANALYST": "A65A",
    "EXECUTIVE": "E69E",
    "CREATOR": "C67C"
}
# Reverse lookup for passwords
PASSWORDS_REV = {v: k for k, v in PASSWORDS.items()}

#File path defined by gradescope
BCHOC_FILE_PATH = os.getenv("BCHOC_FILE_PATH", "bchoc.dat")

# Support for command line arguments
parser = argparse.ArgumentParser(prog="bchoc")

subparsers = parser.add_subparsers(dest="command")

# Add subparser for 'add' command
parser_add = subparsers.add_parser("add", help="Add new evidence item to blockchain")
parser_add.add_argument("-c", "--case_id", required=True, type=str, help="Specifies case identifier that evidence is associated with")
parser_add.add_argument("-i", "--item_id", required=True, type=int, action="append",help="Specifies the evidence item's identifier")
parser_add.add_argument("-g", "--creator", required=True, help="Specifies the creator of the evidence item")
parser_add.add_argument("-p", "--password", required=True, help="Password for access to the blockchain")

# Add subparser for 'checkout' command
parser_checkout = subparsers.add_parser("checkout", help="Add new checkout entry to the CoC for given evidence item")
parser_checkout.add_argument("-i", "--item_id", required=True, type=int, help="Specifies the evidence item's identifier")
parser_checkout.add_argument("-p", "--password", required=True, help="Password for access to the blockchain")

# Add subparser for 'checkin' command
parser_checkin = subparsers.add_parser("checkin", help="Add a new checkin entry to CoC for given evidence item")
parser_checkin.add_argument("-i", "--item_id", required=True, type=int, help="Specifies the evidence item's identifier")
parser_checkin.add_argument("-p", "--password", required=True, help="Password for access to the blockchain")

# Add subparser for 'show' command
parser_show = subparsers.add_parser("show", help="Display information from the blockchain")
show_subparsers = parser_show.add_subparsers(dest="show_command")

# Add subparser for 'show cases' command
parser_show_cases = show_subparsers.add_parser("cases", help="Display list of all cases that have been added")

# Add subparser for 'show items' command
parser_show_items = show_subparsers.add_parser("items", help="Display all items corresponding to the case number")
parser_show_items.add_argument("-c", "--case_id", required=True, help="Specifies case identifier that evidence is associated with")

# Add subparser for 'show history' command
parser_show_history = show_subparsers.add_parser("history", help="Display the blockchain entries for the requested item")
parser_show_history.add_argument("-c", "--case_id", type=str, help="Specifies case identifier that evidence is associated with")
parser_show_history.add_argument("-i", "--item_id", type=int, help="Specifies the evidence item's identifier")
parser_show_history.add_argument("-n", "--num_entries", default=100, type=int, help="Specifies the number of entries to display")
parser_show_history.add_argument("-r", "--reverse", action='store_true', help="Specifies the order of the entries to display")
parser_show_history.add_argument("-p", "--password", required=True, help="Password for access to the blockchain")

# Add subparser for 'remove' command
parser_remove = subparsers.add_parser("remove", help="Prevents further action from being taken on evidence item")
parser_remove.add_argument("-i", "--item_id", required=True, type=int, help="Specifies the evidence item's identifier")
parser_remove.add_argument("-y", "--why", required=True, help="Specifies the reason for removal")
parser_remove.add_argument("-p", "--password", required=True, help="Password for access to the blockchain")

# Add subparser for 'init' command
parser_init = subparsers.add_parser("init", help="Sanity check")

# Add subparser for 'verify' command
parser_verify = subparsers.add_parser("verify", help="Parse the blockchain and validate all entries")

global args

# Block data structure
# Order of fields: prev hash, timestamp, case id (enc), item id (enc), state, creator, owner, data length, data
format_string = "32s d 32s 32s 12s 12s 12s I"
global blocks
blocks = [] # Define list

def init() -> None:
    # Initialize the blockchain
    data = b"Initial block\0"
    # Create block tuple
    genesis_block = [
        b"\0",
        0,
        b"0" * 32,
        b"0" * 32,
        b"INITIAL\0\0\0\0\0",
        b"\0" * 12,
        b"\0" * 12,
        14,
        data
    ]

    # Adds genesis block to global list
    blocks.append(genesis_block)

def block_to_bytes(block:tuple) -> bytes:
    # Pack the block into bytes, don't encrypt the first block
    if (type(block[2]) == str):
        return struct.pack(
            format_string,
            block[0],
            block[1],
            cipher.encrypt(uuid.UUID(block[2]).bytes).hex().encode("utf-8"),
            cipher.encrypt(block[3].to_bytes(16, byteorder='big')).hex().encode("utf-8"),
            block[4],
            block[5],
            block[6],
            block[7]
        ) + block[8]
    else:
        return struct.pack(
            format_string,
            block[0],
            block[1],
            block[2],
            block[3],
            block[4],
            block[5],
            block[6],
            block[7]
        ) + block[8]


def write_blocks() -> None:
    # Clear blockchain file
    open(BCHOC_FILE_PATH, "w").close()

    # Write blocks to file
    with open(BCHOC_FILE_PATH, "ab") as f:
        prev_hash = b"\0"
        # Get initial block as bytes
        for block in blocks:
            # Make sure block is a list
            block = list(block)
            block[0] = prev_hash
            block_bytes = block_to_bytes(block)
            f.write(block_bytes)
            # Store hash of current block for next block
            prev_hash = hashlib.sha256(block_bytes).digest()

def sanity_check() -> bool:
    # Check if the blockchain file exists
    try:
        with open(BCHOC_FILE_PATH, "rb") as f:
            # Grab first block
            header_size = struct.calcsize(format_string) + 14
            first_block = f.read(header_size)

            # Create hash of genesis block
            data = b"Initial block\0"
            genesis_block = [
                b"\0",
                0,
                b"0" * 32,
                b"0" * 32,
                b"INITIAL\0\0\0\0\0",
                b"\0" * 12,
                b"\0" * 12,
                14,
                data
            ]
            genesis_hash = hashlib.sha256(block_to_bytes(genesis_block)).digest()
            # Get hash of first block of file
            block_hash = hashlib.sha256(first_block).digest()
            if (block_hash == genesis_hash):
                return True
            else:
                return False
    except (FileNotFoundError):
        return False
    
def read_blocks() -> None:
    block_counter = 0 # This is just to skip decrypting the first block
    # Read blocks from file
    try:
        with open(BCHOC_FILE_PATH, "rb") as f:
            header_size = struct.calcsize(format_string)
            while True:
                block = f.read(header_size)
                if not block:
                    break
                # Unpack block into fields
                prev_hash, timestamp, case_id, item_id, state, creator, owner, data_length = struct.unpack(format_string, block)
                # Decrypt encrypted fields (case_id and item_id) using AES key (except the first block)
                if block_counter == 0:
                    block_counter += 1
                else:
                    # Turn bytes into string
                    case_id = case_id.decode("utf-8")
                    item_id = item_id.decode("utf-8")
                    # Decode from bytes to uuid and id int
                    case_id = str(uuid.UUID(bytes=cipher.decrypt(bytes.fromhex(case_id))))
                    item_id = int.from_bytes(cipher.decrypt(bytes.fromhex(item_id)), byteorder='big')
                # Grab data to the block
                data = f.read(data_length)

                block_tuple = (prev_hash, timestamp, case_id, item_id, state, creator, owner, data_length, data)
                blocks.append(block_tuple)
    except (FileNotFoundError):
        return

def add_block(case_id, item_id:list, creator, password) -> None:
    # Check password matches that of CREATOR
    if password != "C67C":
        print("Invalid password")
        exit(1)
    # Parse through blockchain to ensure case id is unique
    skip = True
    for block in blocks:
        if skip:
            skip = False
            continue
        if block[2] == case_id:
            print("Case ID already exists")
            exit(1)
        # Parse through blockcahin to ensure each item id is unique
        for id in item_id:
            if block[3] == id:
                print("Item ID already exists")
                exit(1)
    # Create block for each item id
    for id in item_id:
        current_time = time.time()
        # Create new block tuple
        new_block = [
            b"",
            current_time,
            case_id,
            id,
            b"CHECKEDIN",
            creator.encode("utf-8"),
            b"\0",
            0,
            b""
        ]
        # Print to console
        print("Added item: " + str(id) + "\nStatus: CHECKEDIN\nTime of action: " + datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%dT%H:%M:%S.%fZ') + "\n")
        # Appends block to global list
        blocks.append(new_block)

def checkout_block(item_id, password) -> None:
    # Check password belongs to POLICE, LAWYER, ANALYST, EXECUTIVE, or CREATOR
    if password not in PASSWORDS.values():
        print("Invalid password")
        exit(1)
    # Variables to store last seen state and matching block
    last_seen_state = b""
    matching_block = None
    # Parse through blockchain to find last matching item id
    for block in blocks:
        if (item_id == block[3]):
            last_seen_state = block[4]
            matching_block = block
            if (block[4] == b"REMOVED\0\0\0\0\0"):
                print("Item already removed")
                exit(1)
    if (last_seen_state == b"CHECKEDIN\0\0\0"):
        # Create checkin block
        current_time = time.time()
        new_block = [
            0,
            current_time,
            matching_block[2],
            matching_block[3],
            b"CHECKEDOUT\0\0",
            matching_block[5],
            PASSWORDS_REV[password].encode("utf-8"),
            0,
            b""
        ]
        # Add to block list
        blocks.append(new_block)
        print("Case: " + matching_block[2] + "\nItem: " + str(matching_block[3]) + "\nStatus: CHECKEDOUT\nTime of action: " + datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%dT%H:%M:%S.%fZ') + "\n")
        return
    elif (last_seen_state == b"CHECKEDOUT\0\0"):
        print("Item already checked out")
        exit(1)
    else:
        print("Item not found")
        exit(1)

def checkin_block(item_id, password) -> None:
    # Check password belongs to POLICE, LAWYER, ANALYST, EXECUTIVE, or CREATOR
    if password not in PASSWORDS.values():
        print("Invalid password")
        exit(1)
    # Variables to store last seen state and matching block
    last_seen_state = b""
    matching_block = None
    # Parse through blockchain to find last matching item id
    for block in blocks:
        if (item_id == block[3]):
            last_seen_state = block[4]
            matching_block = block
            if (block[4] == b"REMOVED\0\0\0\0\0"):
                print("Item already removed")
                exit(1)
    if (last_seen_state == b"CHECKEDOUT\0\0"):
        # Create checkin block
        current_time = time.time()
        new_block = [
            0,
            current_time,
            matching_block[2],
            matching_block[3],
            b"CHECKEDIN\0\0\0",
            matching_block[5],
            PASSWORDS_REV[password].encode("utf-8"),
            0,
            b""
        ]
        # Add to block list
        blocks.append(new_block)
        print("Case: " + matching_block[2] + "\nItem: " + str(matching_block[3]) + "\nStatus: CHECKEDIN\nTime of action: " + datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%dT%H:%M:%S.%fZ') + "\n")
        return
    elif (last_seen_state == b"CHECKEDIN\0\0\0"):
        print("Item already checked in")
        exit(1)
    else:
        print("Item not found")
        exit(1)

def remove_block(item_id, why, password) -> None:
    # Check password is that of CREATOR
    if password != "C67C":
        print("Invalid password")
        exit(1)
    if why != "DISPOSED" and why != "DESTROYED" and why != "RELEASED":
        print("Invalid reason")
        exit(1)
    # Variables to store last seen state and matching block
    last_seen_state = b""
    matching_block = None
    for block in blocks:
        if (item_id == block[3]):
            last_seen_state = block[4]
            matching_block = block
            if (block[4] == b"REMOVED\0\0\0\0\0" or block[4] == b"DISPOSED\0\0\0" or block[4] == b"DESTROYED\0\0" or block[4] == b"RELEASED\0\0\0"):
                print("Item already removed")
                exit(1)
    if (last_seen_state == b"CHECKEDIN\0\0\0"):
        # Create remove block
        current_time = time.time()
        new_block = [
            0,
            current_time,
            matching_block[2],
            matching_block[3],
            why.encode("utf-8"),
            matching_block[5],
            matching_block[6],
            0,
            b""
        ]
        # Add to block list
        blocks.append(new_block)
        print("Case: " + matching_block[2] + "\nItem: " + str(matching_block[3]) + "\nStatus: REMOVED\nTime of action: " + datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%dT%H:%M:%S.%fZ') + "\n")
        return
    elif (last_seen_state == b"CHECKEDOUT\0\0"):
        print("Item not checked in")
        exit(1)
    else:
        print("Item not found")
        exit(1)

def show_history(case_id, item_id, num_entries, reverse, password) -> None:
    # Create valid genesis block
    genesis_block = [
        b"\0",
        time.time(),
        str(uuid.UUID(int=0)),
        0,
        b"INITIAL\0\0\0\0\0",
        b"\0" * 12,
        b"\0" * 12,
        14,
        b"Initial block\0"
    ]
    blocks.pop(0)
    blocks.insert(0, genesis_block)
    # Check is password is valid
    blocks_printed = 0
    if password not in PASSWORDS.values():
        print("Invalid password")
        exit(1)
    if (reverse):
        # Reverse the list and remove the last block
        blocks.reverse()
    if (case_id == None and item_id == None):
        # Print all blocks
        for block in blocks:
            print("Case: " + str(block[2]) + "\nItem: " + str(block[3]) + "\nAction: " + block[4].decode("utf-8").rstrip('\0') + "\nTime: " + datetime.utcfromtimestamp(block[1]).strftime('%Y-%m-%dT%H:%M:%S.%fZ') + "\n")
            blocks_printed += 1
            if (blocks_printed == num_entries):
                return
    elif (case_id != None and item_id == None):
        # Print all blocks for the case
        for block in blocks:
            if (case_id == block[2]):
                print("Case: " + str(block[2]) + "\nItem: " + str(block[3]) + "\nAction: " + block[4].decode("utf-8").rstrip('\0') + "\nTime: " + datetime.utcfromtimestamp(block[1]).strftime('%Y-%m-%dT%H:%M:%S.%fZ') + "\n")
                blocks_printed += 1
                if (blocks_printed == num_entries):
                    return
    elif (item_id != None):
        # Print all blocks for the item
        for block in blocks:
            if (item_id == block[3]):
                print("Case: " + str(block[2]) + "\nItem: " + str(block[3]) + "\nAction: " + (block[4].decode("utf-8").rstrip('\0')) + "\nTime: " + datetime.utcfromtimestamp(block[1]).strftime('%Y-%m-%dT%H:%M:%S.%fZ') + "\n")
                blocks_printed += 1
                if (blocks_printed == num_entries):
                    return
                
def verify_blocks() -> None:
    # Check the checksum of each block
    for i in range(1, len(blocks)):
        if (blocks[i][0] != hashlib.sha256(block_to_bytes(blocks[i-1])).digest()):
            print("Blockchain is invalid")
            exit(1)
    # Check state order of blocks
    state_dict = {}
    for block in blocks:
        print(block)
        if block[3] not in state_dict:
            if (block[4] == b"CHECKEDIN\0\0\0" or block[4] == b"INITIAL\0\0\0\0\0"):
                # Save the state of the first block appearance
                state_dict[block[3]] = block[4]
            else:
                print("Blockchain is invalid")
                exit(1)
        # Immediately exit if seen item has been remvoed
        elif (state_dict[block[3]] == b'RELEASED\0\0\0\0' or state_dict[block[3]] == b'DESTROYED\0\0\0' or state_dict[block[3]] == b'DISPOSED\0\0\0\0'):
            print("Blockchain is invalid")
            exit(1)
        # Check if state is in correct order (if state is CHECKEDOUT, then previous state must be CHECKEDIN)
        elif (block[4] == b"CHECKEDOUT\0\0" and state_dict[block[3]] != b"CHECKEDIN\0\0\0"):
            print("Blockchain is invalid")
            exit(1)
        elif (block[4] == b"CHECKEDIN\0\0\0" and state_dict[block[3]] != b"CHECKEDOUT\0\0"):
            print("Blockchain is invalid")
            exit(1)
        # Update state of item
        state_dict[block[3]] = block[4]
    print("Blockchain is valid")

def main():
    # Parse command line arguments
    args = parser.parse_args()
    # This is for testcase 001
    try:
        read_blocks()
    except (struct.error):
        exit(1)
    # Run functions based on arguments
    if args.command == "add":
        if not sanity_check():
            init()
            write_blocks()
        add_block(args.case_id, args.item_id, args.creator, args.password)
        write_blocks()
    elif args.command == "checkout":
        checkout_block(args.item_id, args.password)
        write_blocks()
    elif args.command == "checkin":
        checkin_block(args.item_id, args.password)
        write_blocks()
    elif args.command == "show":
        if args.show_command == "cases":
            printed_cases = []
            skip = True
            for block in blocks:
                if block[2] not in printed_cases:
                    if skip:
                        skip = False
                        continue
                    print(block[2])
                    printed_cases.append(block[2])
        elif args.show_command == "items":
            printed_items = []
            for block in blocks:
                if block[2] == args.case_id:
                    if block[3] not in printed_items:
                        print(str(block[3]) + "\n")
                        printed_items.append(block[3])
        elif args.show_command == "history":
            show_history(args.case_id, args.item_id, args.num_entries, args.reverse, args.password)
    elif args.command == "remove":
        remove_block(args.item_id, args.why, args.password)
        write_blocks()
    elif args.command == "init":
        # Check if blockchain file exists with a genesis block, create one if it doesn't
        if not sanity_check():
            init()
            write_blocks()
            print("Blockchain file not found. Created INITIAL block.\n")
        else:
            print("Blockchain file found with INITIAL block.\n")
    elif args.command == "verify":
        verify_blocks()
    else:
        print("Invalid command")
        exit(1)    
    exit(0)

main()