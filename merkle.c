#include "merkle.h"

#include <malloc.h>
#include <string.h>
#include <assert.h>

#include "sha256.h"
#include "paging.h"
#include "vm.h"

_Static_assert(sizeof(merkle_node_t) == 64,
        "merkle_node_t is not 64 bytes!");

#define MERK_NODES_PER_PAGE (RISCV_PAGE_SIZE / sizeof(merkle_node_t))

typedef struct merkle_page_freelist {
    uint64_t free[MERK_NODES_PER_PAGE / 64];
    uint16_t free_count;
    bool in_freelist;
    struct merkle_page_freelist *next;
} merkle_page_freelist_t;

_Static_assert(sizeof(merkle_page_freelist_t) <= sizeof(merkle_node_t),
        "merkle_page_freelist_t does not fit in one merkle_node_t!");

static merkle_page_freelist_t *merk_alloc_page(void)
{
    void *page = (void *)__alloc_backing_page();
    merkle_page_freelist_t *free_list = (merkle_page_freelist_t *)page;
    memset(free_list, 0, sizeof(*free_list));

    for (size_t i = 0; i < MERK_NODES_PER_PAGE; i += 64) {
        size_t this_page_nodes = MERK_NODES_PER_PAGE - i;
        free_list->free[i / 64] = (this_page_nodes < 64) * (1ull << this_page_nodes) - 1;
    }
    free_list->free[0] &= ~(uint64_t)1;
    free_list->free_count = MERK_NODES_PER_PAGE - 1;

    return free_list;
}

static merkle_page_freelist_t *merk_free_list = NULL;

static merkle_node_t *merk_reserve_node_in_page(merkle_page_freelist_t *free_list)
{
    if (!free_list->free_count)
        return NULL;

    for (size_t i = 0; i < MERK_NODES_PER_PAGE / 64; i++) {
        if (free_list->free[i]) {
            size_t free_idx = __builtin_ctzll(free_list->free[i]);
            free_list->free[i] &= ~(1ull << free_idx);
            free_list->free_count--;

            merkle_node_t *page = (merkle_node_t *)free_list;
            assert(free_idx != 0);

            return page + free_idx;
        }
    }
    return NULL;
}

static merkle_node_t *merk_alloc_node(void)
{
    while (merk_free_list && merk_free_list->free_count == 0) {
        // Clear out the unfree lists
        merk_free_list->in_freelist = false;
        merk_free_list = merk_free_list->next;
    }
    
    if (!merk_free_list) {
        merk_free_list = merk_alloc_page();
        merk_free_list->in_freelist = true;
    }

    merkle_node_t *out = merk_reserve_node_in_page(merk_free_list);
    return out;
}

static void merk_free_node(merkle_node_t *node)
{
    uintptr_t page = (uintptr_t)node & ~(RISCV_PAGE_SIZE - 1);
    merkle_page_freelist_t *free_list = (merkle_page_freelist_t *)page;
    size_t idx = node - (merkle_node_t *)page;

    assert(idx < MERK_NODES_PER_PAGE);
    assert((free_list->free[idx / 64] & (1ull << (idx % 64))) == 0);

    free_list->free[idx / 64] |= (1ull << (idx % 64));
    free_list->free_count++;

    if (!free_list->in_freelist) {
        free_list->next = merk_free_list;
        merk_free_list = free_list;
        free_list->in_freelist = true;
    }
}


static bool merk_verify_single_node(merkle_node_t *node, merkle_node_t *left, merkle_node_t *right)
{
    SHA256_CTX hasher;
    uint8_t calculated_hash[32];

    sha256_init(&hasher);

    if (left) {
        sha256_update(&hasher, left->hash, 32);
    }
    if (right) {
        sha256_update(&hasher, right->hash, 32);
    }

    if (!left && !right) {
        return true;
    }

    sha256_final(&hasher, calculated_hash);
    return memcmp(calculated_hash, node->hash, 32) == 0;
}

bool merk_verify(volatile merkle_node_t *root, uintptr_t key, uint8_t hash[32])
{
    merkle_node_t node = *root;
    if (!root->right)
        return false;

    merkle_node_t left;
    merkle_node_t right = *root->right;

    // Verify root node
    if (!merk_verify_single_node(&node, NULL, &right)) {
        printf("Error verifying root!\n");
        return false;
    }
    
    node = right;

    for (int i = 0;; i++) {
        // node is a leaf, so return its hash check
        if (!node.left && !node.right) {
            return memcmp(hash, node.hash, 32) == 0;
        }

        // Load in the next layer. This is to prevent race conditions
        if (node.left)
            left = *(volatile merkle_node_t *)node.left;
        if (node.right)
            right = *(volatile merkle_node_t *)node.right;

        bool node_ok = merk_verify_single_node(
            &node,
            node.left ? &left : NULL,
            node.right ? &right : NULL
        );
        if (!node_ok) {
            printf("Error at node with ptr %zx in layer %d\n", node.ptr, i);
            return false;
        }

        // BST traversal
        if (key < node.ptr) {
            node = left;
        } else {
            node = right;
        }
    }
}

void merk_insert(merkle_node_t *root, uintptr_t key, uint8_t hash[32])
{
#define MERK_MAX_DEPTH 20
    SHA256_CTX hasher;

    merkle_node_t **intermediate_nodes[MERK_MAX_DEPTH] = {};

    merkle_node_t *node = merk_alloc_node();
    *node = (merkle_node_t) {
        .ptr = key,
    };

    uint8_t lowest_hash[32];

    memcpy(lowest_hash, hash, 32);
    memcpy(node->hash, lowest_hash, 32);

    if (!root->right) {
        root->right = node;
        return;
    }

    intermediate_nodes[0] = &root;
    int i;

    for (i = 1; i < MERK_MAX_DEPTH; i++) {
        merkle_node_t *parent = *intermediate_nodes[i - 1];
        
        if (!parent->left && !parent->right) {
            merkle_node_t *sibling = parent;

            // parent is a child node
            if (node->ptr < sibling->ptr) {
                *intermediate_nodes[i - 1] = parent = merk_alloc_node();

                *parent = (merkle_node_t) {
                    .ptr = sibling->ptr,
                    .left = node,
                    .right = sibling,
                };
            } else if (node->ptr > sibling->ptr) {
                *intermediate_nodes[i - 1] = parent = merk_alloc_node();

                *parent = (merkle_node_t) {
                    .ptr = node->ptr,
                    .left = sibling,
                    .right = node,
                };
            } else {
                i--;
                *intermediate_nodes[i] = node;
                merk_free_node(sibling);
            }
            break;
        }

        if (node->ptr < parent->ptr) {
            if (!parent->left) {
                parent->left = node;
                break;
            } else {
                intermediate_nodes[i] = &parent->left;
            }
        } else {
            if (!parent->right) {
                parent->right = node;
                break;
            } else {
                intermediate_nodes[i] = &parent->right;
            }
        }
    }

    assert(i != MERK_MAX_DEPTH);

    for (i = i - 1; i >= 0; i--) {
        sha256_init(&hasher);
        merkle_node_t *parent_ptr = *intermediate_nodes[i];
        merkle_node_t parent = *parent_ptr;
        assert(!memcmp(lowest_hash, node->hash, 32));

        if (node == parent.left) {
            sha256_update(&hasher, lowest_hash, 32);
            if (parent.right)
                sha256_update(&hasher, parent.right->hash, 32);
        } else {
            assert(node == parent.right);
            if (parent.left)
                sha256_update(&hasher, parent.left->hash, 32);
            sha256_update(&hasher, lowest_hash, 32);
        }

        sha256_final(&hasher, lowest_hash);
        memcpy(parent.hash, lowest_hash, 32);
        *parent_ptr = parent;
        node = parent_ptr;
    }
}

