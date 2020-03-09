#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

typedef union merkle_node {
    struct {
        uintptr_t ptr;
        uint8_t hash[32];
        union merkle_node *left, *right;
    };
    struct {
        uint64_t raw_words[8];
    };
} merkle_node_t;

void merk_insert(merkle_node_t *root, uintptr_t key, uint8_t hash[32]);
bool merk_verify(volatile merkle_node_t *root, uintptr_t key, uint8_t hash_out[32]);
