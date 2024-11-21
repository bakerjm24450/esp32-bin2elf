# esp32-bin2elf
Simple tool for converting ESP32 flash dump into a bare-bones ELF file.
The intended typical workflow:
- Read a .bin file from the ESP32 flash memory
- Use esp32-bin2elf to extract .elf files for the app partitions and .dat files for the data partitions
- Use esp32-nvs2csv to convert any NVS data partitions to CSV files
- For Xiaomi based devices such as Yeelight, use esp32-mi2csv to convert a mi-specific NVS data partition to a CSV file

Usage:

    python esp32-bin2elf.py yourfile.bin
    python esp32-nvs2csv.py yourfile.data.nvs.nvs.dat
    python esp32-min2csv.py yourfile.data.unknown.minvs.dat
