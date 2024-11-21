"""Convert ESP32 NVS flash dump to CSV file

This program processes an NVS data partition from the flash memory of an 
ESP32 (see the esp32-bin2elf.py program for a tool to extract the
data partions from a flash dump). This program creates a CSV file with 
the information about all written and/or erased NVS entries.

The NVS partition is organized into 4KB pages. Each page starts with
a 32-byte header followed by a 32-byte bitmap of the state of each entry.
After that, up to 126 key-value entries are included on the page.
"""

import argparse
import struct
import os
from enum import IntEnum
import warnings
from operator import attrgetter

class NVSEntryState(IntEnum):
    """Possible states of an entry in NVS
    """
    Erased  = 0
    Written = 2
    Empty   = 3

class NVSPageState(IntEnum):
    """Possible states for page in NVS
    """
    Corrupted = 0
    Erasing   = 0xfffffff8
    Full      = 0xfffffffc
    Active    = 0xfffffffe
    Empty     = 0xffffffff

class NVSDataType(IntEnum):
    """Types of data stored in NVS
    """
    uint8_t    = 0x01
    uint16_t   = 0x02
    uint32_t   = 0x04
    uint64_t   = 0x08
    int8_t     = 0x11
    int16_t    = 0x12
    int32_t    = 0x14
    int64_t    = 0x18
    string     = 0x21
    blob_data  = 0x42
    blob_index = 0x48

class NVSEntry:
    """A key-value pair in the NVS (Non Volatile Storage) partition.

    Attributes:
        ns (int) : namespace id (index into list of namespace strings)
        datatype (NVSDataType) : datatype for this value
        span (int) : how many table entries this key-value pair takes up
        chunkIndex (int) : index of blob-data for blob types (0xff for other types)
        crc (int) : crc32 checksum of bytes of entry
        dataCrc (int) : crc32 checksum of data bytes for strings and blobs
        size (int) : size of value in bytes
        key (str) : ASCII string containing key name
        value (int | str | bytes) : data value
        state (NVSEntryState) : empty, written, or erased
    """

    namespaces : dict[int, str] = {0 : "Namespace"}
    """Dictionary of namespaces (str)"""

    def __init__(self, entryData : bytes, state : NVSEntryState) -> None:
        """Initialize a key-value entry.

        Note that for strings and blobs, the data value will not be set here. It
        must be read separately since string and blob data spans multiple entries.

        Args:
            entryData (bytes) : raw bytes of the entry
            state (NVSEntryState) : state of entry (empty, written, erased)

        """
        self.ns : int = 0
        self.datatype : NVSDataType = NVSDataType.uint8_t
        self.span : int = 0
        self.chunkIndex : int = 0
        self.crc : int = 0
        self.dataCrc : int = 0
        self.size : int = 0
        self.key : str = ""
        self.value = None
        self.state : NVSEntryState = state

        # read entry info
        self.ns, datatype, self.span, self.chunkIndex, \
            self.crc, self.key \
            = struct.unpack('<BBBBI16s', entryData[0:24])
        
        # data is the last 8 bytes of entry
        data = entryData[24:32]

        # convert datatype to enum
        self.datatype = NVSDataType(datatype)

        # strip any trailing nulls from key name
        self.key = self.key.rstrip(b'\x00').decode('utf-8')

        # if entry is non-empty, then get data value
        if self.state != NVSEntryState.Empty:
            # figure out the size and parse the data, depending on datatype
            match self.datatype:
                case NVSDataType.uint8_t: 
                    self.size = 1
                    self.value = struct.unpack('<B', data[0:1])[0]
                case NVSDataType.uint16_t:
                    self.size = 2
                    self.value = struct.unpack('<H', data[0:2])[0]
                case NVSDataType.uint32_t:
                    self.size = 4
                    self.value = struct.unpack('<I', data[0:4])[0]
                case NVSDataType.uint64_t:
                    self.size = 8
                    self.value = struct.unpack('<Q', data[0:8])[0]
                case NVSDataType.int8_t: 
                    self.size = 1
                    self.value = struct.unpack('<b', data[0:1])[0]
                case NVSDataType.int16_t:
                    self.size = 2
                    self.value = struct.unpack('<h', data[0:2])[0]
                case NVSDataType.int32_t:
                    self.size = 4
                    self.value = struct.unpack('<i', data[0:4])[0]
                case NVSDataType.int64_t:
                    self.size = 8
                    self.value = struct.unpack('<q', data[0:8])[0]
                case NVSDataType.string:
                    # size is stored in data bytes
                    self.size, _, self.dataCrc = struct.unpack('<HHI', data[0:8])

                    # we have to read the string data separately since it's
                    # stored in the following entry(s). We do that later.
                    self.value = None
                case NVSDataType.blob_data:
                    # size of blob is stored in data bytes
                    self.size, _, self.dataCrc = struct.unpack('<HHI', data[0:8])

                    # we have to read the blob data separately since it's 
                    # stored in the following entry(s). We do that later.
                    self.value = None
                case NVSDataType.blob_index:
                    # size and chunkCount are stored in data bytes (ignore chunkStart)
                    self.size, self.value = struct.unpack('<IH', data[0:6])
                case _:
                    # unrecognized data type
                    warnings.warn(f'Unexpected data type {self.datatype.key} in NVS entry')
                    self.size = 0
                    self.value = None

            # is this a new namespace (it is if in namespace 0)
            if self.ns == 0:
                # add it to the list of namespaces
                NVSEntry.namespaces.update({self.value : self.key})

    def __str__(self) -> str:
        """Returns a string representation of the key-value"""
        return f'{NVSEntryState(self.state).name},{self.datatype.name},{self.size},'\
                + f'{NVSEntry.namespaces[self.ns]},{self.key},{self.value}'
    
    def readStrValue(self, data : bytes) -> None:
        """Reads a string from NVS 
        
        The size of the string is given by self.size, and self.datatype should be string

        Args:
            data (bytes) : data containing the string
        """
        # make sure this is a string
        if self.datatype == NVSDataType.string:
            self.value = struct.unpack('<{}s'.format(self.size), data[0:self.size])[0]

            # strip any trailing null chars and convert to string
            self.value = self.value.rstrip(b'\x00').decode('utf-8')
        else:
            warnings.warn(f'Trying to read non-string data type {self.dataType.key} as string')
            self.value = None

    def readBlobValue(self, data : bytes) -> None:
        """Reads a blob from NVS 
        
        The size of the blob is given by self.size, and self.datatype should be blob_data.
        The data is converted to a string of hex digits so that we can print it neatly.
        Also note that we assume the blob does not span multiple NVS pages.

        Args:
            data (bytes) : data containing the blob
        """
        # make sure this is a blob
        if self.datatype == NVSDataType.blob_data:
            # convert to a string of hex digits
            self.value = "b'" + bytes(data[0:self.size]).hex() + "'"
        else:
            warnings.warn(f'Trying to read non-blob data type {self.dataType.key} as blob')
            self.value = None

class NVSPage:
    """A page of NVS storage

    The page begins with a 32-byte header with the following format (size of each field
    in bytes is listed in parentheses)
        state (4) | sequence num (4) | version (1) | unused (19) | CRC32 (4)

    The CRC32 is calculated over the sequence number, version, and unused bytes in the
    header.
    
    The next 32 bytes are a bitmap containing the state of each entry (empty, written,
    or erased). The states for 4 entries are packed into each byte.

    After the state bitmap, there follows up to 126 entries or key-value pairs. Each
    32-byte entry has the following format:
        Namespace index (1) | type (1) | span (1) | chunkIndex (1) | CRC32 (4) |
             key (32) | data (8)
    For strings, blob data, and blob indexes, the data bytes have unique formats.

    See the Espressif documentation for more info on the NVS format.
    
    Attributes:
        state (NVSPageState) : if the page is full, active, erased, or empty
        seqNum (int) : logical page number
        version (int) : NVS format version
        crc (int) : CRC32 checksum of the page header
        entries (list[NVSEntry]) : list of NVS key-value pairs on this page
    """

    # size of a page in bytes
    PAGE_SIZE = 4096

    # number of bytes per entry
    ENTRY_SIZE = 32

    # number of entries on a page (header and bitmap take up space of 2 entries)
    NUM_ENTRIES = 126

    def __init__(self, pageData : bytes) -> None:
        """Read a page from NVS partition
        
        Args:
            pageData (bytes) : raw data bytes containing the NVS page
        """

        # parse the page header
        self.state, self.seqNum, self.version, _, self.crc = struct.unpack(
            '<IIB19sI', 
            pageData[0:32]
            )
        
        # start with an empty list for the key-value pairs
        self.entries : list[NVSEntry] = []

        # if this is an active or full page, then continue parsing
        if self.state == NVSPageState.Active or self.state == NVSPageState.Full:
            # get the entry state bitmap (128 entries, packed 4 to a byte)
            entryStateBitmap = struct.unpack('<32B', pageData[32:64])

            # unpack the entries into a list
            entryState : list[NVSEntryState] = []
            for i in range(NVSPage.ENTRY_SIZE):
                # get the states of the 4 pages packed into this byte
                entryState.append(entryStateBitmap[i] & 0x3)
                entryState.append((entryStateBitmap[i] >> 2) & 0x3)
                entryState.append((entryStateBitmap[i] >> 4) & 0x3)
                entryState.append((entryStateBitmap[i] >> 6) & 0x3)
            
            # read the entries
            entryNum = 0
            while entryNum < NVSPage.NUM_ENTRIES:
                # calculate the addr on the page for this entry
                #  (header takes up first two 32-byte blocks)
                addr = (entryNum + 2) * NVSPage.ENTRY_SIZE

                # if this entry is not empty, then parse it
                if entryState[entryNum] != NVSEntryState.Empty:
                    entry = NVSEntry(pageData[addr:addr+NVSPage.ENTRY_SIZE],
                                     entryState[entryNum])

                    # if this is a string, then read string value from next entries
                    if entry.datatype == NVSDataType.string:
                        entry.readStrValue(pageData[addr+NVSPage.ENTRY_SIZE:])

                    # if this is a blob, then read blob data from next entries
                    elif entry.datatype == NVSDataType.blob_data:
                        entry.readBlobValue(pageData[addr+NVSPage.ENTRY_SIZE:])

                    # add entry to the list
                    self.entries.append(entry)

                    # advance to next entry
                    entryNum += entry.span
                
                # if empty, then just go on to next entry
                else:
                    entryNum += 1

def extractNVSEntries(filename : str, printWritten : bool, printErased : bool) -> None:
    """Parses the NVS data from a file and saves the data as a CSV file. 

    Parameters:
    -----------
    filename (str) : Name of the file containing the NVS data. 
                        The CSV file will have the same name but replacing the 
                        file extension with .csv
    printWritten (bool) : Whether or not to write the Written entries to the CSV file
    printErased (bool) : Whether or not to write the Erased entries to the CSV file
    """
    # open the file and read the data
    with open(filename, mode="rb") as f:
        imageData = f.read()

        # create a list of NVS pages
        pages : list[NVSPage] = []

        # parse each page
        for pageAddr in range(0, len(imageData), NVSPage.PAGE_SIZE):
            page = NVSPage(imageData[pageAddr : pageAddr + NVSPage.PAGE_SIZE])

            # if page has data, then add to our list
            if page.state == NVSPageState.Active or page.state == NVSPageState.Full:
                pages.append(page)

        # sort the pages by sequence number
        pages.sort(key=attrgetter('seqNum'))

    # build the output file name
    basefilename = os.path.splitext(filename)[0]
    outfilename = basefilename + ".csv"

    with open(outfilename, mode="w") as f:
        # write a header to the file
        f.write('status,type,size,namespace,name,value\n')

        # output each page's data
        for page in pages:
            for entry in page.entries:
                if (printWritten and entry.state == NVSEntryState.Written) \
                    or (printErased and entry.state == NVSEntryState.Erased):
                    f.write(str(entry) + '\n')
                
def main():
    # parse the command line arguments
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        'filename',
        type=str,
        help='The name of the file containing the ESP32 NVS data')
    
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
    extractNVSEntries(args.filename, args.written, args.erased)

if __name__ == "__main__":
    main()