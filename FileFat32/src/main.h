#ifndef MAIN_H
#define MAIN_H

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>

#define DISK_SIZE (20 * 1024 * 1024) // 20 MB
#define ATTR_DIRECTORY 0x10
#define FAT32_EOC 0x0FFFFFF8 // End of cluster chain
#define ROOT_CLUSTER 2

#define CLUSTER_SIZE                                                           \
  boot_sector.bytes_per_sector *boot_sector.sectors_per_cluster
#define DIR_SIZE                                                               \
  boot_sector.bytes_per_sector *boot_sector.sectors_per_cluster /              \
      sizeof(DirEntry)

#define FIRST_SECTOR(cluster)                                                  \
  (boot_sector.reserved_sectors +                                              \
   boot_sector.number_of_fats * boot_sector.sectors_per_fat_32) +              \
      (cluster - 2) * boot_sector.sectors_per_cluster

typedef struct {
  uint8_t jump_code[3];        // Jump code to the bootloader
  char oem_name[8];            // OEM name (e.g., "MSWIN4.1")
  uint16_t bytes_per_sector;   // Sector size in bytes (typically 512)
  uint8_t sectors_per_cluster; // Number of sectors per cluster
  uint16_t reserved_sectors;   // Number of reserved sectors
  uint8_t number_of_fats;      // Number of File Allocation Tables (FAT)
  uint16_t reserved1;          // Reserved (was root_entries)
  uint16_t reserved2;          // Reserved (was total_sectors_16)
  uint8_t media_descriptor;    // Media descriptor (e.g., 0xF8 for hard disk)
  uint16_t reserved3;          // Reserved (was sectors_per_fat)
  uint16_t sectors_per_track;  // Number of sectors per track
  uint16_t number_of_heads;    // Number of heads
  uint32_t hidden_sectors;     // Number of hidden sectors
  uint32_t total_sectors_32;   // Total sectors count (for FAT32)
  uint32_t sectors_per_fat_32; // Sectors per FAT (for FAT32)
  uint16_t flags;              // Flags
  uint16_t version;            // Filesystem version
  uint32_t root_cluster;       // Root directory cluster number (for FAT32)
  uint16_t fs_info_sector;     // FS Information sector number
  uint16_t backup_boot_sector; // Backup boot sector number
  uint8_t reserved4[12];       // Reserved
  uint8_t drive_number;        // Drive number
  uint8_t reserved5;           // Reserved
  uint8_t boot_signature;      // Boot signature (0x29)
  uint32_t volume_id;          // Volume ID
  char volume_label[11];       // Volume label
  char fs_type[8];             // Filesystem type (e.g., "FAT32   ")
  uint8_t boot_code[420];      // Boot code
  uint16_t boot_signature2;    // Boot signature (0xAA55)
} __attribute__((packed)) BootSector;

typedef struct {
  char name[11];                // File/directory name (8.3 format)
  uint8_t attributes;           // Attributes (read-only, hidden, system, etc.)
  uint8_t reserved;             // Reserved
  uint8_t creation_time_tenths; // Tenths of seconds at creation time
  uint16_t creation_time;       // Creation time
  uint16_t creation_date;       // Creation date
  uint16_t last_access_date;    // Last access date
  uint16_t first_cluster_high;  // High part of the first cluster number
  uint16_t last_write_time;     // Last write time
  uint16_t last_write_date;     // Last write date
  uint16_t first_cluster_low;   // Low part of the first cluster number
  uint32_t file_size;           // File size in bytes
} __attribute__((packed)) DirEntry;

// Global variables
extern int disk_fd;
extern char *disk_path;
extern BootSector boot_sector;
extern uint32_t current_cluster;

// Boot sector
void format_disk();
void read_boot_sector();
void write_boot_sector();

// Work with FAT32 Table
void write_fat_entry(const uint32_t cluster, uint32_t value);
uint32_t read_fat_entry(const uint32_t cluster);
uint32_t find_free_cluster();
uint32_t get_next_cluster(const uint32_t cluster);

// Work with clusters
void clear_cluster(const uint32_t cluster);
uint32_t read_dir_entries(const uint32_t cluster, DirEntry *entries);
void write_dir_entries(const uint32_t cluster, const DirEntry *entries);

// Find Files and directories
uint32_t find_file_or_dir(const char *name, const uint32_t dir_cluster,
                          DirEntry *output);
uint32_t find_file_or_dir_full_path(const char *full_path, DirEntry *output);

// Work with directories
uint8_t is_directory_cluster_full(const uint32_t cluster);
uint32_t get_write_cluster_for_dir_entry(uint32_t cluster);

// Commands
void cmd_cd(const char *path);
void cmd_format();
void cmd_ls(const char *path);
void cmd_mkdir(const char *name);
void cmd_touch(const char *name);

#endif
