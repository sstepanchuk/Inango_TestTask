#ifndef H_REMOVE_ELEMENT
#define H_REMOVE_ELEMENT

void remove_elements(void *array, const unsigned short element_size,
                     unsigned short *indices, const unsigned short num_indices,
                     unsigned short *num_elements);

#endif