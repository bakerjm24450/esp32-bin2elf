"""Convert ESP32 Xiaomi / Yeelight Mi NVS flash dump to CSV file

This program processes a data partition from the flash memory of a
Ydeelight ESP32 (see the esp32-bin2elf.py program for a tool to extract the
data partions from a flash dump). This program creates a CSV file with 
the information about all written and/or erased name-value entries. 

The Xiaomi / Yeelight stores data in an undocumented format different
from the NVS format that Espressif uses. 

The entries are variable length and appear to use the following structure:

    16-byte header:
        Magic number : 2 bytes 0x55 0xAA
        Unused or unknown? : 2 bytes
        CRC checksum : 4 bytes
        Data length : 2 bytes, little-endian order
        Sequence number : 2 bytes (which entry this is)
        Key length : 1 byte
        Unused or unknown : 3 bytes

    Followed by the variable-length key (ASCII chars, but not null-terminated)
    Followed by the variable-length data value (most are ASCII chars)
        """

import argparse
import struct
import os
from enum import IntEnum
import warnings

class MiNVSEntryState(IntEnum):
    """Possible states of an entry in MiNVS storage
    """
    Erased = 0xfffe
    Written = 0xffff

class MiNVSEntry:
    """A key-value pair in the Mi NVS (Non Volatile Storage) partition.

    Attributes:
        seqNum (int) : sequence number of this entry
        size (int) : total size of this entry
        state (MiNVSEntryState) : written (0xffff) or erased (0xfffe)
        crc (int) : crc32 checksum of bytes of entry
        dataSize (int) : size of data value in bytes
        keyLength (int) : length of key name in bytes
        key (str) : ASCII string containing key name
        value (str) : data value
    """

    def __init__(self, entryData : bytes) -> None:
        """Initialize a key-value entry.

        Args:
            entryData (bytes) : raw bytes of the entry

        """
        MAGIC_NUMBER : int = 0xAA55

        self.seqNum : int = 0
        self.size : int = 16
        self.crc : int = 0
        self.dataSize : int = 0
        self.keyLength : int = 0
        self.key : str = ""
        self.value : str = ""
        self.state : MiNVSEntryState = MiNVSEntryState.Erased

        # read entry header
        magic, state, self.crc, self.dataSize, self.seqNum, self.keyLength, \
            padding1, padding2, padding3 \
            = struct.unpack('<HHIHHBBBB', entryData[0:16])
        
        # is this a valid entry?
        if magic == MAGIC_NUMBER:
            # check unused fields
            if (padding1 != 0xff) or (padding2 != 0xff) or (padding3 != 0xff):
                warnings.warn(f'Unused padding bytes of header: {hex(padding1)} {hex(padding2)} {hex(padding3)}, expected 0xff ff ff')

            # convert state to our datatype
            self.state = MiNVSEntryState(state)

            # get key name (follows the header)
            self.key = struct.unpack('<{}s'.format(self.keyLength), \
                                     entryData[self.size:self.size+self.keyLength])[0]
            self.key = self.key.decode('utf-8')

            # add length of key to the size
            self.size += self.keyLength

            # get data bytes as string (follows the key)
            self.value = struct.unpack('<{}s'.format(self.dataSize), \
                            entryData[self.size : self.size+self.dataSize])[0]
            self.value = self.value.decode('utf-8')

            # kind of a kludge -- if there are unprintable chars, we'll treat as str of bytes
            if not self.value.isprintable():
                self.value = "b'" + \
                    bytes(entryData[self.size : self.size+self.dataSize]).hex() + "'"
                
            # add data size to total size
            self.size += self.dataSize

    def __str__(self) -> str:
        """Returns a string representation of the key-value"""
        return f'{self.seqNum},{self.state.name},{self.dataSize},{self.key},{self.value}'
    
def extractMiNVSEntries(filename : str, printWritten : bool, printErased : bool) -> None:
    """Parses the Mi NVS data from a file and saves the data as a CSV file. 

    Parameters:
    -----------
    filename : str
        Name of the file containing the Mi NVS data. The CSV file will have the same
        name but replacing the file extension with .csv
    printWritten : bool
        Whether or not to write the Written entries to the CSV file
    printErased : bool
        Whether or not to write the Erased entries to the CSV file        
    """
    # open the file and read the data
    with open(filename, mode="rb") as f:
        imageData = f.read()

    # create a list of Mi NVS entries
    entries : list[MiNVSEntry] = []

    addr : int = 0

    while addr < len(imageData):
        entry = MiNVSEntry(imageData[addr : ])

        # if valid entry, then add to our list
        if entry.seqNum != 0xffff:
            entries.append(entry)

            # advance the addr to the next entry
            addr += entry.size
        else:
            # found an invalid entry so we must be done
            addr = len(imageData)
            
    # build the output file name
    basefilename = os.path.splitext(filename)[0]
    outfilename = basefilename + ".csv"

    with open(outfilename, mode="w") as f:
        # write a header to the file
        f.write('seqNum,state,size,name,value\n')

        # output each entry's data
        for entry in entries:
            if (printWritten and entry.state == MiNVSEntryState.Written) \
                or (printErased and entry.state == MiNVSEntryState.Erased):

                f.write(str(entry) + '\n')
                
def main():
    # parse the command line arguments
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        'filename',
        type=str,
        help='The name of the file containing the Yeelight MiNVS data')
    
    parser.add_argument(
        '-w', '--written',
        default=True,
        action=argparse.BooleanOptionalAction,
        help='Extract all written entries'
    )
    parser.add_argument(
        '-e', '--erased',
        action='store_true',
        help='Extract all erased entries'
    )

    args = parser.parse_args()

    # process the file
    extractMiNVSEntries(args.filename, args.written, args.erased)

if __name__ == "__main__":
    main()