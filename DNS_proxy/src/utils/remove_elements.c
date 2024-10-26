#include "remove_elements.h"

void remove_elements(void *array, const unsigned short element_size,
                     unsigned short *indices, const unsigned short num_indices,
                     unsigned short *num_elements) {
  char *arr = (char *)array;
  unsigned short write_pos = 0, index_to_remove = 0;

  // Sort indices array for efficient removal (optional but helpful for large
  // index lists)
  for (unsigned short i = 1; i < num_indices; i++) {
    for (unsigned short j = i; j > 0 && indices[j - 1] > indices[j]; j--) {
      unsigned short temp = indices[j];
      indices[j] = indices[j - 1];
      indices[j - 1] = temp;
    }
  }

  for (unsigned short read_pos = 0; read_pos < *num_elements; read_pos++) {
    // Check if the current position is in the removal list
    if (index_to_remove < num_indices && read_pos == indices[index_to_remove]) {
      index_to_remove++;
      continue; // Skip the element that needs to be removed
    }

    // Only move data if necessary (i.e., if read_pos != write_pos)
    if (write_pos != read_pos) {
      // Copy the current element to the write position
      for (unsigned short byte = 0; byte < element_size; byte++) {
        arr[write_pos * element_size + byte] =
            arr[read_pos * element_size + byte];
      }
    }
    write_pos++;
  }

  // Update the number of elements in the array
  *num_elements = write_pos;
}