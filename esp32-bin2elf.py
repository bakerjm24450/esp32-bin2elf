"""Convert ESP32 flash dump to ELF file(s)

This program processes a dump of the flash memory of an ESP32. It 
creates a separate ELF file for the bootloader and each APP partition
that it finds, and separate files for each data partition.

The program assumes that the bootloader is at address 0x1000 and a
partition table is at address 0x8000 in the flash dump. The locations
of the other app and data partitions are found in the partition table.
"""

import argparse
import struct
import functools
import hashlib
import os
import warnings
from enum import IntEnum

class PartitionType(IntEnum):
    """Possible partition types -- app or data
    """
    app = 0x00
    data = 0x01
    user = 0x40
    unknown = 0xff

    @classmethod
    def _missing_(cls, value):
        # valid user values are 0x40 to 0xfe
        if PartitionType.user <= value < PartitionType.unknown:
            return PartitionType.user
        # otherwise it's unknown
        else:
            return PartitionType.unknown
            
class AppSubType(IntEnum):
    """Sub-types of app partitions
    """
    factory = 0x00
    ota_0 = 0x10
    ota_1 = 0x11
    ota_2 = 0x12
    ota_3 = 0x13
    ota_4 = 0x14
    ota_5 = 0x15
    ota_6 = 0x16
    ota_7 = 0x17
    ota_8 = 0x18
    ota_9 = 0x19
    ota_10 = 0x1a
    ota_11 = 0x1b
    ota_12 = 0x1c
    ota_13 = 0x1d
    ota_14 = 0x1e
    ota_15 = 0x1f
    unknown = 0xff

    @classmethod
    def _missing_(cls, value):
        return AppSubType.unknown

class DataSubType(IntEnum):
    """Sub-types for data partitions
    """
    ota = 0x00
    phy = 0x01
    nvs = 0x02
    coredump = 0x03
    nvs_keys = 0x04
    efuse = 0x05
    undefined = 0x06
    fat = 0x81
    spiffs = 0x82
    littlefs = 0x83
    unknown = 0xff

    @classmethod
    def _missing_(cls, value):
        return DataSubType.unknown

class UserSubType(IntEnum):
    """Sub-types for user partitions
    """
    user = 0x00

class UnknownSubType(IntEnum):
    """Sub-types for unknown partition types
    """
    unknown = 0x00

def parseAppImage(imageData : bytes) -> tuple[int, list]:
    """Parses an app partition
    
    Args:
        imageData (bytes) : Array of bytes containing the program header and segments

    Returns:
        tuple[int, list] : tuple containing the entry point address and a list
            of program segments, each of which is a tuple with the segment
            address and bytes array

    """

    # helper function to calculate checksum of the app partition
    def calculateChecksum(segments):
        """ Calculate the checksum for the data segments. 
        
        The checksum value is the XOR of all data in the segments with 
        the value 0xef
        """
        csum = 0xef

        for seg in segments:
            csum = functools.reduce(lambda x, y: x ^ y, seg['data'], csum)

        return csum

    BIN_MAGIC_NUMBER = 0xe9

    # keep track of our offset into the data
    offset = 0

    # parse the program file header
    (magic, numSegments, flashMode, flashSizeFreq, entry) = struct.unpack(
        '<BBBBI', 
        imageData[offset:offset+8]
    )
    offset += 8     # advance the offset past the program header
    
    if magic != BIN_MAGIC_NUMBER:
        # maybe throw an exception here?
        warnings.warn(f'Invalid app program file header at offset {offset}')
        return 0, None
    
    if numSegments == 0:
        # nothing in the file so skip it
        warnings.warn('Found empty app partition')
        return 0, None
    
    # parse the extended header
    (_, chipId, _, minChipRev, maxChipRev, _, hasHash) = struct.unpack(
        '<IHBHHIB', imageData[offset:offset+16]
    )
    offset += 16   # advance the offset past the extended header

    # parse each segment
    segments = []
    for _ in range(numSegments):
        # get address and size of this segment
        (address, size) = struct.unpack('<II', imageData[offset: offset+8])
        offset += 8  # advaance past the header

        # read the data if present
        if size > 0:
            segmentData = imageData[offset:offset + size]
            offset += size   # advance to after the data

            # add to our list of segments
            segments.append({'address' : address, 'data' : segmentData})

    # advance offset to location of checksum for 
    offset += 15 - (offset % 16)    # advance to 1 less than mulitple of 16

    # compare checksums of all data in the segments
    if imageData[offset] != calculateChecksum(segments):
        warnings.warn('Invalid checksum in app image')
        return 0, None
    
    offset += 1     # advance past the checksum
    
    # look for SHA256 hash if present
    if hasHash:
        # calculate SHA256 hash of entire image
        h = hashlib.sha256()
        h.update(imageData[0:offset])
        
        if h.digest() != imageData[offset:offset+32]:
            warnings.warn('Invalid SHA256 hash for app image')
    
    return entry, segments

def writeElfFile(elfname : str, entryAddr : int, segments : list) -> None :
    """ Writes an ELF file with the given name. 
    
    Note this file will only contain the ELF header, the program header 
    table, and the segment data. There is no section header or string table.

    Args:
        elfname (str) : name of ELF file
        entryAddr (int) : entry address for program
        segments (list) : list of ELF segments
    """
    with open(elfname+'.elf', mode="wb") as f:
        # write ELF header
        elfHeader = struct.pack('<4s5B7x2H5I6H',
                                b'\x7fELF',
                                1,              # 32-bit
                                1,              # little-endian
                                1,              # version
                                0,              # target os
                                0,              # abi version
                                0x02,           # executable file
                                0x005e,         # Xtensa
                                1,              # version
                                entryAddr,
                                0x34,           # offset to program header table
                                0,              # offset to section header table
                                0x300,          # flags (not sure where this is from?)
                                0x34,           # size of elf header
                                0x20,           # size of program header entry
                                len(segments),
                                0x28,           # size of section header entry
                                0,              # number of sections
                                0)              # index to string header table
        f.write(elfHeader)

        # determine offset for first segment (after elf header and program table).
        #  note each table entry is 0x20 bytes
        offset = len(elfHeader) + len(segments) * 0x20

        # write program header table
        for segment in segments:
            segmentEntry = struct.pack('<8I',
                                       0x1,     # loadable
                                       offset,  # location of this segment
                                       segment["address"],
                                       segment["address"],
                                       len(segment["data"]),
                                       len(segment["data"]),
                                       0x7,     # flags
                                       0        # alignment
                                       )
            f.write(segmentEntry)

            # figure out offset to the next segment
            offset += len(segment["data"])
        
        # write segments
        for segment in segments:
            f.write(segment["data"])

def image2elf(imageData : bytes, filename : str):
    """Extracts an app partition as an ELF file.
    
    Args:
        imageData (bytes) : Array of bytes containing the program header and segments
        filename (str) : Name of ELF file to write (.elf will be appended)

    """

    # parse the image
    entry, segments = parseAppImage(imageData)

    # did we get an image?
    if segments is not None:
        writeElfFile(filename, entry, segments)

def  image2dat(imageData : bytes, filename : str) -> None:
    """Writes a data partion to a separate file
    
    Args:
        imageData (bytes) : Array of bytes containing the data partition
        filename (str) : Name of file to write (.dat will be appended)

    """        

    with open(filename+'.dat', mode='wb') as f:
        f.write(imageData)

def processPartitionTableEntry(imageData : bytes, 
                               offset : int, 
                               filename : str) -> None:
    """Processes an entry in the partition table

    If the entry is an app, then an ELF file is created. 
    If the entry is data, then a .dat file (raw binary) is created.
    
    Args:
        imageData (bytes): Array containing the entire flash image
        offset (int) : Offset in imageData for this partition table entry
        filename (str) : Base filename for the resulting elf or dat file (the type, sub-type,
            and partition name will be appended to it, along with .elf or .dat)


    """
    # parse the entry from the table (note that magic number has already been verified
    typeNum, subtypeNum, addr, size, name, flags = struct.unpack(
        '<BBLL16sL', 
        imageData[offset+2 : offset+32])

    # strip any extra nulls from name
    name = name.rstrip(b'\x00').decode(encoding='utf-8')

    # determine type and sub-type
    type = PartitionType(typeNum)
    match type:
        case PartitionType.app:
            subtype = AppSubType(subtypeNum)
        case PartitionType.data:
            subtype = DataSubType(subtypeNum)
        case PartitionType.user:
            subtype = UserSubType.user
        case PartitionType.unknown:
            subtype = UnknownSubType.unknown
        case _:
            warnings.warn(f'Unexpected partition type {typenum}')
            subtype = UnknownSubType.unknown


    outFileName = filename + "." + type.name + "." + subtype.name + "." + name

    # app or data?
    if type == PartitionType.app:
        # create ELF file
        image2elf(imageData[addr:addr+size], outFileName)
    else:
        # data (or unknown and we'll treat like data)
        image2dat(imageData[addr:addr+size], outFileName)

def parsePartitionTable(imageData : bytes, addr : int, filename : str) -> None : 
    """Process an ESP32 partition table
    
    For each entry in the partition table, we either read a data segment and
    write a .dat file, or we read an app image and write an ELF file.

    Each table entry is 32 bytes long and starts with the magic bytes 0xaa 0x50.
    After the last table entry, there is an optional MD5 checksum, which is preceded
    by the magic bytes 0xeb 0xeb. The checksum is calculated over all bytes in
    the table up to (but not including) the checksum itself.

    Args:
        imageData (bytes) :
            Array of bytes containing the flash dump. Because entries in the 
            partition table are indexed from the beginning of flash. this array
            contains the entire flash dump.

        addr (int) :
            Starting address of the partition table in imageData

        filename (str) :
            Base filename to use for the .dat and .elf files. Each file will be
            named like filename.type.subtype.partitionName.dat or 
            filename.type.subtype.partitionName.elf

    """
    # each valid entry starts with 0xaa 0x50 (0x50aa in little-endian ordering)
    PARTITION_TABLE_ENTRY_MAGIC_NUMBER = 0x50aa
    PARTITION_TABLE_CHECKSUM_MAGIC_NUMBER = 0xebeb

    # begin with starting addr
    offset = addr

    # process each entry
    while struct.unpack('<H', imageData[offset:offset+2])[0] == PARTITION_TABLE_ENTRY_MAGIC_NUMBER:
        processPartitionTableEntry(imageData, offset, filename)

        # skip to next table entry
        offset += 32

    # look for MD5 checksum
    if struct.unpack('<H', imageData[offset:offset+2]) == PARTITION_TABLE_CHECKSUM_MAGIC_NUMBER:
        m = hashlib.md5()

        # calculate checksum of table
        m.update(imageData[addr:offset])

        if imageData[offset+16:offset+32] != m.digest():
            warnings.warn('WARNING -- MD5 checksum mismatch in partition table at addr ' + str(addr))

def extractEsp32Files(filename : str, bootloader : int, partitionTable : int) -> None:
    """Process an ESP32 flash dump, extracting app and data partitions

    A separate ELF file is written for each app partition and data
    partitions are also written to individual files.

    Arguments:
        filename (str) : Name of file containing flash dump
        bootloader (int) : address of bootloader code
        partitionTable (int) : address of partition table

    """
    # open file and process it
    with open(filename, mode="rb") as f:
        imageData = f.read()

    baseFilename = os.path.splitext(filename)[0]

    # convert the bootloader code to elf
    image2elf(imageData[bootloader:], baseFilename+'.bootloader')

    # partition table contains info on other apps and data
    parsePartitionTable(imageData, partitionTable, baseFilename)

def main():
    # parse the command line arguments
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        'filename',
        type=str,
        help='The name of the file containing the ESP32 flash dump')
    
    # specify location of bootloader
    parser.add_argument('-b', '--bootloader', type=int, default=0x1000, 
                        help='address of bootloader code')
    
    # specify location of partition table
    parser.add_argument('-p', '--partition_table', type=int, default=0x8000,
                        help='address of partition table')

    args = parser.parse_args()

    # process the file
    extractEsp32Files(args.filename, args.bootloader, args.partition_table)

if __name__ == "__main__":
    main()