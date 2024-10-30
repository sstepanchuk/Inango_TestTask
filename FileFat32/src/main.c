#include "main.h"

int disk_fd;
char *disk_path;
// const char *d_path = "./fat32file";
char cmd_path[256] = "/";
BootSector boot_sector;
uint32_t current_cluster;

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <disk_path>\n", argv[0]);
    return 1;
  }

  disk_path = argv[1];
  disk_fd = open(/*d_path*/ disk_path, O_RDWR | O_CREAT, 0644);
  if (disk_fd == -1) {
    perror("open");
    return 1;
  }

  if (lseek(disk_fd, DISK_SIZE - 1, SEEK_SET) == -1) {
    perror("lseek");
    return 1;
  }
  if (write(disk_fd, "", 1) != 1) {
    perror("write");
    return 1;
  }

  read_boot_sector();
  if (boot_sector.boot_signature != 0x29 ||
      boot_sector.boot_signature2 != 0xAA55) {
    fprintf(stderr, "Unknown disk format\n");
  }

  current_cluster = boot_sector.root_cluster;

  char command[256];
  char *token;

  while (1) {
    printf("%s>", cmd_path);

    if (fgets(command, sizeof(command), stdin) == NULL) {
      break;
    }

    command[strcspn(command, "\n")] = 0;

    token = strtok(command, " ");
    if (token == NULL) {
      continue;
    }

    if (strcmp(token, "format") == 0) {
      cmd_format();
    } else if (boot_sector.boot_signature == 0x29 &&
               boot_sector.boot_signature2 == 0xAA55) {
      if (strcmp(token, "cd") == 0) {
        token = strtok(NULL, " ");
        if (token != NULL) {
          cmd_cd(token);
        } else {
          fprintf(stderr, "Usage: cd <path>\n");
        }
      } else if (strcmp(token, "ls") == 0) {
        token = strtok(NULL, " ");
        cmd_ls(token);
      } else if (strcmp(token, "mkdir") == 0) {
        token = strtok(NULL, " ");
        if (token != NULL) {
          cmd_mkdir(token);
        } else {
          fprintf(stderr, "Usage: mkdir <name>\n");
        }
      } else if (strcmp(token, "touch") == 0) {
        token = strtok(NULL, " ");
        if (token != NULL) {
          cmd_touch(token);
        } else {
          fprintf(stderr, "Usage: touch <name>\n");
        }
      } else if (strcmp(token, "exit") == 0) {
        break;
      } else {
        fprintf(stderr, "Unknown command: %s\n", token);
      }
    } else
      fprintf(stderr, "Unknown disk format\n");
  }
  close(disk_fd);
  return 0;
}

void write_boot_sector() {
  if (lseek(disk_fd, 0, SEEK_SET) == -1) {
    perror("lseek");
    exit(1);
  }

  if (write(disk_fd, &boot_sector, sizeof(boot_sector)) == -1) {
    perror("write");
    exit(1);
  }
}

void read_boot_sector() {
  if (lseek(disk_fd, 0, SEEK_SET) == -1) {
    perror("lseek");
    exit(1);
  }

  if (read(disk_fd, &boot_sector, sizeof(boot_sector)) == -1) {
    perror("read");
    exit(1);
  }
}

void clear_cluster(const uint32_t cluster) {
  uint32_t first_sector = FIRST_SECTOR(cluster);

  uint8_t *buffer = calloc(CLUSTER_SIZE, 1);
  if (!buffer) {
    perror("ERROR: Can't alloc memory");
    return;
  }

  lseek(disk_fd, first_sector * boot_sector.bytes_per_sector, SEEK_SET);
  write(disk_fd, buffer, CLUSTER_SIZE);

  free(buffer);
}

uint32_t find_free_cluster() {
  uint32_t cluster = boot_sector.root_cluster;
  uint32_t fat_size = boot_sector.number_of_fats *
                      boot_sector.sectors_per_fat_32 *
                      boot_sector.bytes_per_sector;
  uint32_t fat_start =
      boot_sector.reserved_sectors * boot_sector.bytes_per_sector;

  uint8_t *fat = malloc(fat_size);
  if (!fat) {
    perror("ERROR: Can't alloc memory");
    return 0;
  }

  lseek(disk_fd, fat_start, SEEK_SET);
  if (read(disk_fd, fat, fat_size) != fat_size) {
    perror("ERROR: Can't read from disc file");
    free(fat);
    return 0;
  }

  while (cluster < (fat_size / sizeof(uint32_t))) {
    uint32_t entry =
        le32toh(*(uint32_t *)&fat[cluster * sizeof(uint32_t)]) & 0x0FFFFFFF;
    if (entry == 0) {
      free(fat);
      return cluster;
    }
    cluster++;
  }

  free(fat);
  return 0;
}

void write_fat_entry(const uint32_t cluster, uint32_t value) {
  value = htole32(value);
  uint32_t fat_offset = cluster * sizeof(uint32_t);
  uint32_t fat_sector = boot_sector.reserved_sectors +
                        (fat_offset / boot_sector.bytes_per_sector);
  uint32_t sector_offset = fat_offset % boot_sector.bytes_per_sector;

  lseek(disk_fd, fat_sector * boot_sector.bytes_per_sector + sector_offset,
        SEEK_SET);
  if (write(disk_fd, &value, sizeof(value)) != sizeof(value)) {
    perror("ERROR write to FAT");
    return;
  }

  fat_sector += boot_sector.sectors_per_fat_32;
  lseek(disk_fd, fat_sector * boot_sector.bytes_per_sector + sector_offset,
        SEEK_SET);
  if (write(disk_fd, &value, sizeof(value)) != sizeof(value)) {
    perror("ERROR write to second copy of FAT");
  }
}

uint32_t read_fat_entry(const uint32_t cluster) {
  uint32_t fat_offset = cluster * sizeof(uint32_t);

  uint32_t fat_sector = boot_sector.reserved_sectors +
                        (fat_offset / boot_sector.bytes_per_sector);
  uint32_t sector_offset = fat_offset % boot_sector.bytes_per_sector;

  lseek(disk_fd, fat_sector * boot_sector.bytes_per_sector + sector_offset,
        SEEK_SET);

  uint32_t entry;
  if (read(disk_fd, &entry, sizeof(entry)) != sizeof(entry)) {
    perror("ERROR reading from FAT");
    return 0;
  }

  entry = le32toh(entry);
  return entry;
}

uint32_t get_next_cluster(const uint32_t cluster) {
  uint32_t next_cluster = read_fat_entry(cluster);
  return (next_cluster >= FAT32_EOC) ? 0 : next_cluster;
}

uint32_t read_dir_entries(const uint32_t cluster, DirEntry *entries) {
  uint32_t first_sector = FIRST_SECTOR(cluster);
  lseek(disk_fd, first_sector * boot_sector.bytes_per_sector, SEEK_SET);
  read(disk_fd, entries,
       boot_sector.bytes_per_sector * boot_sector.sectors_per_cluster);

  return get_next_cluster(cluster);
}

void write_dir_entries(const uint32_t cluster, const DirEntry *entries) {
  uint32_t first_sector = FIRST_SECTOR(cluster);
  lseek(disk_fd, first_sector * boot_sector.bytes_per_sector, SEEK_SET);
  write(disk_fd, entries,
        boot_sector.bytes_per_sector * boot_sector.sectors_per_cluster);
}

uint8_t is_directory_cluster_full(const uint32_t cluster) {
  DirEntry entries[DIR_SIZE];
  read_dir_entries(cluster, entries);

  for (uint32_t i = 0; i < DIR_SIZE; i++)
    if (entries[i].name[0] == 0x00)
      return 0;
  return 1;
}

uint32_t get_write_cluster_for_dir_entry(uint32_t cluster) {
  uint8_t is_cluster_full;
  uint32_t next_cluster;
  do {
    next_cluster = get_next_cluster(next_cluster);
    if (next_cluster) {
      cluster = next_cluster;
      continue;
    }
  } while (next_cluster);

  if (is_directory_cluster_full(cluster)) {
    next_cluster = find_free_cluster();
    if (!next_cluster)
      return 0;
    write_fat_entry(cluster, next_cluster);
    write_fat_entry(next_cluster, FAT32_EOC);
    clear_cluster(next_cluster);

    cluster = next_cluster;
  }

  return cluster;
}

uint32_t find_file_or_dir(const char *name, const uint32_t dir_cluster,
                          DirEntry *output) {
  DirEntry entries[DIR_SIZE];
  uint32_t next_cluster;
  char entry_name[12];
  do {
    next_cluster = read_dir_entries(dir_cluster, entries);

    for (int i = 0; i < DIR_SIZE; i++) {
      if (entries[i].name[0] == 0x00 || entries[i].name[0] == 0xE5)
        continue;

      memcpy(entry_name, entries[i].name, 11);
      entry_name[11] = '\0';

      if (strcasecmp(entry_name, name) == 0) {
        if (output != NULL)
          *output = entries[i];
        return (((uint32_t)entries[i].first_cluster_high) << 16) |
               entries[i].first_cluster_low;
      }
    }
  } while (next_cluster);

  return 0;
}

uint32_t find_file_or_dir_full_path(const char *full_path, DirEntry *output) {
  if (full_path == NULL || strlen(full_path) == 0 || full_path[0] != '/') {
    return 0;
  }

  uint32_t current_cluster = boot_sector.root_cluster;

  char *path_copy = strdup(full_path);
  char *token = strtok(path_copy, "/");

  while (token != NULL) {
    uint32_t next_cluster = find_file_or_dir(token, current_cluster, output);

    if (next_cluster == 0) {
      free(path_copy);
      return 0;
    }

    current_cluster = next_cluster;
    token = strtok(NULL, "/");
  }

  free(path_copy);
  return current_cluster;
}

void format_disk() {
  memset(&boot_sector, 0, sizeof(boot_sector));
  boot_sector.jump_code[0] = 0xEB;
  boot_sector.jump_code[1] = 0x58;
  boot_sector.jump_code[2] = 0x90;
  strcpy(boot_sector.oem_name, "MY NAME");
  boot_sector.bytes_per_sector = 512;
  boot_sector.sectors_per_cluster = 8;
  boot_sector.reserved_sectors = 32;
  boot_sector.number_of_fats = 2;
  boot_sector.media_descriptor = 0xF8;
  boot_sector.sectors_per_track = 63;
  boot_sector.number_of_heads = 255;
  boot_sector.hidden_sectors = 0;
  boot_sector.total_sectors_32 = DISK_SIZE / boot_sector.bytes_per_sector;
  boot_sector.sectors_per_fat_32 = 0; // Will calculated later
  boot_sector.flags = 0x0000;
  boot_sector.version = 0x0000;
  boot_sector.root_cluster = ROOT_CLUSTER;
  boot_sector.fs_info_sector = 1;
  boot_sector.backup_boot_sector = 6;
  boot_sector.drive_number = 0x80;
  boot_sector.boot_signature = 0x29;
  boot_sector.volume_id = 0x12345678;
  strcpy(boot_sector.volume_label, "NO NAME");
  strcpy(boot_sector.fs_type, "FAT32");
  boot_sector.boot_signature2 = 0xAA55;

  uint32_t total_clusters =
      (boot_sector.total_sectors_32 - boot_sector.reserved_sectors) /
      boot_sector.sectors_per_cluster;
  uint32_t fat_size = (total_clusters * sizeof(uint32_t) + 511) / 512;
  boot_sector.sectors_per_fat_32 = fat_size;

  write_boot_sector();

  lseek(disk_fd, boot_sector.reserved_sectors * boot_sector.bytes_per_sector,
        SEEK_SET);
  uint8_t *fat =
      calloc(boot_sector.sectors_per_fat_32 * boot_sector.bytes_per_sector, 1);
  // RESERVED
  fat[0] = 0xF8;
  fat[1] = 0xFF;
  fat[2] = 0xFF;
  fat[3] = 0x0F;
  // RESERVED
  fat[8] = 0xFF;
  fat[9] = 0xFF;
  fat[10] = 0xFF;
  fat[11] = 0x0F;
  // Write two fat copies
  write(disk_fd, fat,
        boot_sector.sectors_per_fat_32 * boot_sector.bytes_per_sector);
  write(disk_fd, fat,
        boot_sector.sectors_per_fat_32 * boot_sector.bytes_per_sector);
  free(fat);

  // Create root directory
  lseek(disk_fd,
        (boot_sector.reserved_sectors +
         boot_sector.number_of_fats * boot_sector.sectors_per_fat_32) *
            boot_sector.bytes_per_sector,
        SEEK_SET);
  uint8_t *root_dir =
      calloc(boot_sector.bytes_per_sector * boot_sector.sectors_per_cluster, 1);
  write(disk_fd, root_dir,
        boot_sector.bytes_per_sector * boot_sector.sectors_per_cluster);
  free(root_dir);

  printf("Ok\n");
  current_cluster = boot_sector.root_cluster;

  cmd_path[0] = '/';
  cmd_path[1] = '\0';
}

void cmd_cd(const char *path) {
  if (path == NULL || strlen(path) == 0) {
    return;
  }

  if (strcmp(path, "/") == 0) {
    current_cluster = boot_sector.root_cluster;
    strcpy(cmd_path, path);
    return;
  }

  DirEntry entry;
  uint32_t cluster = find_file_or_dir_full_path(path, &entry);
  if (cluster && entry.attributes & ATTR_DIRECTORY) {
    current_cluster = cluster;
    strcpy(cmd_path, path);
  } else
    fprintf(stderr, "ERROR: No such directory: %s\n", path);
}

void cmd_format() {
  format_disk();
  printf("Ok\n");
}

void cmd_ls(const char *path) {
  uint32_t dir_cluster = current_cluster;

  if (path != NULL && strlen(path)) {
    DirEntry dir_entry;
    dir_cluster = find_file_or_dir_full_path(path, &dir_entry);
    if (!dir_cluster || dir_entry.attributes & 0x10 == 0) {
      fprintf(stderr, "ERROR: No such directory: %s\n", path);
      return;
    }
  }

  DirEntry entries[DIR_SIZE];
  uint32_t next_cluster;
  char entry_name[12];

  do {
    next_cluster = read_dir_entries(dir_cluster, entries);

    for (int i = 0; i < DIR_SIZE; i++) {
      if (entries[i].name[0] == 0x00 || entries[i].name[0] == 0xE5)
        continue;

      strncpy(entry_name, entries[i].name, 11);
      entry_name[11] = '\0';

      if (entries[i].attributes & ATTR_DIRECTORY)
        strcat(entry_name, "/");

      printf("%s ", entry_name);
    }
  } while (next_cluster);

  printf("\n");
}

void cmd_mkdir(const char *name) {
  if (strlen(name) > 11) {
    fprintf(stderr, "ERROR: Invalid directory name: %s\n", name);
    return;
  }

  if (find_file_or_dir(name, current_cluster, NULL)) {
    fprintf(stderr, "ERROR: File or Directory already exists: %s\n", name);
    return;
  }

  uint32_t parent_dir_cluster =
      get_write_cluster_for_dir_entry(current_cluster);

  if (!parent_dir_cluster) {
    fprintf(stderr, "ERROR: No free clusters available.\n");
    return;
  }

  DirEntry entries[DIR_SIZE];
  read_dir_entries(parent_dir_cluster, entries);
  int free_entry_index = -1;

  for (uint32_t i = 0; i < DIR_SIZE; i++) {
    if (entries[i].name[0] == 0x00 || entries[i].name[0] == 0xE5) {
      free_entry_index = i;
      break;
    }
  }

  if (free_entry_index == -1) {
    fprintf(stderr, "ERROR: Program error.\n");
    return;
  }
  uint32_t new_dir_cluster = find_free_cluster();
  if (new_dir_cluster == 0) {
    fprintf(stderr, "ERROR: No free clusters available.\n");
    return;
  }

  DirEntry new_dir;
  memset(&new_dir, 0, sizeof(new_dir));
  strncpy(new_dir.name, name, 11);
  new_dir.attributes = 0x10;
  new_dir.first_cluster_low = new_dir_cluster & 0xFFFF;
  new_dir.first_cluster_high = (new_dir_cluster >> 16) & 0xFFFF;

  entries[free_entry_index] = new_dir;
  write_dir_entries(parent_dir_cluster, entries);

  write_fat_entry(new_dir_cluster, FAT32_EOC);

  memset(entries, 0, sizeof(DirEntry) * DIR_SIZE);
  strncpy(entries[0].name, ".", 11);
  entries[0].attributes = 0x10;
  entries[0].first_cluster_low = new_dir_cluster & 0xFFFF;
  entries[0].first_cluster_high = (new_dir_cluster >> 16) & 0xFFFF;

  strncpy(entries[1].name, "..", 11);
  entries[1].attributes = 0x10;
  entries[1].first_cluster_low = parent_dir_cluster & 0xFFFF;
  entries[1].first_cluster_high = (parent_dir_cluster >> 16) & 0xFFFF;

  write_dir_entries(new_dir_cluster, entries);

  printf("Ok\n");
}

void cmd_touch(const char *name) {
  if (strlen(name) > 11) {
    fprintf(stderr, "ERROR: Invalid file name: %s\n", name);
    return;
  }

  if (find_file_or_dir(name, current_cluster, NULL)) {
    fprintf(stderr, "ERROR: File or Directory already exists: %s\n", name);
    return;
  }

  uint32_t parent_dir_cluster =
      get_write_cluster_for_dir_entry(current_cluster);

  if (!parent_dir_cluster) {
    fprintf(stderr, "ERROR: No free clusters available.\n");
    return;
  }

  DirEntry entries[DIR_SIZE];
  read_dir_entries(parent_dir_cluster, entries);
  int free_entry_index = -1;

  for (uint32_t i = 0; i < DIR_SIZE; i++) {
    if (entries[i].name[0] == 0x00 || entries[i].name[0] == 0xE5) {
      free_entry_index = i;
      break;
    }
  }

  if (free_entry_index == -1) {
    fprintf(stderr, "ERROR: Program error.\n");
    return;
  }

  DirEntry new_file;
  memset(&new_file, 0, sizeof(new_file));
  strncpy(new_file.name, name, 11);
  new_file.attributes = 0x20;

  entries[free_entry_index] = new_file;
  write_dir_entries(current_cluster, entries);

  printf("Ok\n");
}
