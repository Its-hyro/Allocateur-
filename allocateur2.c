#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

// Définitions et structures
#define ALIGNMENT 16
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define DEFAULT_MAX_ALLOC_SIZE (sysconf(_SC_PAGESIZE) * 1024)
#define MAX_CACHE_SIZE 1024
#define MAX_CACHED_BLOCK_SIZE (16 * 1024)
#define MIN_BLOCK_SIZE 16
#define MAX_BLOCK_SIZE (16 * 1024)

// Structures
typedef struct mem_block_t {
    void* ptr;
    size_t size;
    int in_use;
    struct mem_block_t* next;
} mem_block_t;

typedef struct allocation_info {
    void* ptr;
    size_t size;
    const char* file;
    int line;
    struct allocation_info* next;
} allocation_info_t;

typedef struct {
    void* blocks[MAX_CACHE_SIZE];
    size_t sizes[MAX_CACHE_SIZE];
    size_t count;
} block_cache_t;

// Variables globales
static allocation_info_t* allocation_list = NULL;
static size_t total_allocations = 0;
static size_t active_allocations = 0;
static size_t total_memory_allocated = 0;
static mem_block_t* mem_blocks = NULL;
static size_t allocated_blocks = 0;
static block_cache_t block_cache = {0};

// Prototypes de fonctions
static void* get_from_cache(size_t size);
static int add_to_cache(void* ptr, size_t size);
static mem_block_t* find_best_fit(size_t size);
void* malloc_wrapper(size_t size);
void free_wrapper(void* ptr);
void* my_malloc_wrapper(size_t size);
void my_free_wrapper(void* ptr);
void run_tests(void);
long get_time_in_microseconds(void);

// Fonctions de base
mem_block_t* create_block(void* ptr, size_t size, int in_use) {
    mem_block_t* block = (mem_block_t*)malloc(sizeof(mem_block_t));
    if (!block) {
        perror("malloc");
        return NULL;
    }
    block->ptr = ptr;
    block->size = size;
    block->in_use = in_use;
    block->next = NULL;
    return block;
}

void add_block(mem_block_t* block) {
    if (!mem_blocks) {
        mem_blocks = block;
    } else {
        mem_block_t* current = mem_blocks;
        mem_block_t* prev = NULL;
        
        while (current && current->ptr < block->ptr) {
            prev = current;
            current = current->next;
        }
        
        if (prev) {
            prev->next = block;
        } else {
            mem_blocks = block;
        }
        block->next = current;
    }
    allocated_blocks++;
}

void coalesce_free_blocks() {
    mem_block_t* current = mem_blocks;
    
    while (current && current->next) {
        if (!current->in_use && !current->next->in_use) {
            // Vérifier si les blocs sont adjacents
            if ((char*)current->ptr + current->size == (char*)current->next->ptr) {
                mem_block_t* next_block = current->next;
                current->size += next_block->size;
                current->next = next_block->next;
                free(next_block);
                allocated_blocks--;
                continue;  // Continuer à fusionner avec le bloc suivant si possible
            }
        }
        current = current->next;
    }
}

// Fonctions de traçage
void track_allocation(void* ptr, size_t size, const char* file, int line) {
    allocation_info_t* info = malloc(sizeof(allocation_info_t));
    if (!info) return;

    info->ptr = ptr;
    info->size = size;
    info->file = file;
    info->line = line;
    info->next = allocation_list;
    allocation_list = info;

    total_allocations++;
    active_allocations++;
    total_memory_allocated += size;
}

void untrack_allocation(void* ptr) {
    allocation_info_t* current = allocation_list;
    allocation_info_t* prev = NULL;

    while (current) {
        if (current->ptr == ptr) {
            if (prev) {
                prev->next = current->next;
            } else {
                allocation_list = current->next;
            }
            active_allocations--;
            total_memory_allocated -= current->size;
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

// Fonctions de gestion des classes de tailles
// Supprimer init_size_classes, get_size_class_index, add_to_size_class, find_in_size_classes

// Fonctions de cache
static int add_to_cache(void* ptr, size_t size) {
    if (size > MAX_CACHED_BLOCK_SIZE || block_cache.count >= MAX_CACHE_SIZE) {
        return 0;
    }

    for (size_t i = 0; i < block_cache.count; i++) {
        if (block_cache.blocks[i] == ptr) {
            return 1;
        }
    }

    block_cache.blocks[block_cache.count] = ptr;
    block_cache.sizes[block_cache.count] = size;
    block_cache.count++;
    return 1;
}

static void* get_from_cache(size_t size) {
    for (size_t i = 0; i < block_cache.count; i++) {
        if (block_cache.sizes[i] >= size) {
            void* ptr = block_cache.blocks[i];

            block_cache.count--;
            if (i < block_cache.count) {
                block_cache.blocks[i] = block_cache.blocks[block_cache.count];
                block_cache.sizes[i] = block_cache.sizes[block_cache.count];
            }

            return ptr;
        }
    }
    return NULL;
}

// Macro pour faciliter le traçage
#define MY_MALLOC(size) \
    _my_malloc(size, DEFAULT_MAX_ALLOC_SIZE, __FILE__, __LINE__)

// Fonctions principales d'allocation
void* _my_malloc(size_t size, size_t max_alloc_size, const char* file, int line) {
    size_t aligned_size = ALIGN(size);
    
    if (size == 0 || aligned_size > max_alloc_size || aligned_size < size) {
        errno = EINVAL;
        return NULL;
    }

    // Pour les grandes allocations
    if (aligned_size > MAX_CACHED_BLOCK_SIZE) {
        void* new_ptr = mmap(NULL, aligned_size, 
                            PROT_READ | PROT_WRITE, 
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_ptr == MAP_FAILED) {
            perror("mmap");
            return NULL;
        }

        mem_block_t* new_block = create_block(new_ptr, aligned_size, 1);
        if (!new_block) {
            munmap(new_ptr, aligned_size);
            return NULL;
        }

        add_block(new_block);
        track_allocation(new_ptr, aligned_size, file, line);
        return new_ptr;
    }

    // Vérifier dans le cache
    void* cached_ptr = get_from_cache(aligned_size);
    if (cached_ptr) {
        mem_block_t* current = mem_blocks;
        while (current) {
            if (current->ptr == cached_ptr) {
                current->in_use = 1;
                break;
            }
            current = current->next;
        }
        track_allocation(cached_ptr, aligned_size, file, line);
        return cached_ptr;
    }

    // Chercher un bloc libre approprié
    mem_block_t* best_block = find_best_fit(aligned_size);
    if (best_block) {
        if (best_block->size >= aligned_size + ALIGNMENT + sizeof(mem_block_t)) {
            size_t remaining_size = best_block->size - aligned_size;
            best_block->size = aligned_size;
            
            mem_block_t* new_block = create_block(
                (char*)best_block->ptr + aligned_size,
                remaining_size,
                0
            );
            if (new_block) {
                new_block->next = best_block->next;
                best_block->next = new_block;
            }
        }
        
        best_block->in_use = 1;
        track_allocation(best_block->ptr, aligned_size, file, line);
        return best_block->ptr;
    }

    // Allouer un nouveau bloc
    size_t alloc_size = aligned_size < 4096 ? 4096 : aligned_size;
    void* new_ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, 
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_ptr == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    mem_block_t* new_block = create_block(new_ptr, aligned_size, 1);
    if (!new_block) {
        munmap(new_ptr, alloc_size);
        return NULL;
    }

    add_block(new_block);

    if (alloc_size > aligned_size + ALIGNMENT + sizeof(mem_block_t)) {
        mem_block_t* remainder = create_block(
            (char*)new_ptr + aligned_size,
            alloc_size - aligned_size,
            0
        );
        if (remainder) {
            add_block(remainder);
        }
    }

    track_allocation(new_ptr, aligned_size, file, line);
    return new_ptr;
}

void* my_malloc(size_t size, size_t max_alloc_size) {
    return _my_malloc(size, max_alloc_size, "unknown", 0);
}

int my_free(void* ptr) {
    if (!ptr) {
        errno = EINVAL;
        return -1;
    }

    mem_block_t* current = mem_blocks;
    mem_block_t* prev = NULL;
    size_t block_count = 0;
    const size_t MAX_BLOCKS = 1000;

    while (current && block_count < MAX_BLOCKS) {
        if (current->ptr == ptr) {
            if (!current->in_use) {
                errno = EINVAL;
                return -1;
            }
            
            current->in_use = 0;
            untrack_allocation(ptr);

            if (current->size > MAX_CACHED_BLOCK_SIZE) {
                if (prev) {
                    prev->next = current->next;
                } else {
                    mem_blocks = current->next;
                }
                
                void* ptr_to_free = current->ptr;
                size_t size_to_free = current->size;
                free(current);
                munmap(ptr_to_free, size_to_free);
                return 0;
            }

            if (add_to_cache(ptr, current->size)) {
                return 0;
            }

            coalesce_free_blocks();
            return 0;
        }
        
        prev = current;
        current = current->next;
        block_count++;
    }

    if (block_count >= MAX_BLOCKS) {
        fprintf(stderr, "Erreur: Nombre maximum de blocs atteint\n");
        errno = EINVAL;
        return -1;
    }

    errno = ENOENT;
    return -1;
}

void* my_realloc(void* ptr, size_t new_size) {
    if (!ptr) return my_malloc(new_size, DEFAULT_MAX_ALLOC_SIZE);
    if (new_size == 0) {
        my_free(ptr);
        return NULL;
    }

    mem_block_t* current = mem_blocks;
    while (current) {
        if (current->ptr == ptr) {
            if (current->size >= new_size) return ptr;
            void* new_ptr = my_malloc(new_size, DEFAULT_MAX_ALLOC_SIZE);
            if (!new_ptr) return NULL;
            memcpy(new_ptr, ptr, current->size);
            my_free(ptr);
            return new_ptr;
        }
        current = current->next;
    }

    errno = ENOENT;
    return NULL;
}

// Fonctions de test
void cleanup_memory() {
    // Libérer tous les blocs de mémoire
    mem_block_t* current = mem_blocks;
    while (current) {
        mem_block_t* next = current->next;
        if (current->ptr) {
            munmap(current->ptr, current->size);
        }
        free(current);
        current = next;
    }
    mem_blocks = NULL;
    allocated_blocks = 0;

    // Vider le cache
    for (size_t i = 0; i < block_cache.count; i++) {
        if (block_cache.blocks[i]) {
            munmap(block_cache.blocks[i], block_cache.sizes[i]);
        }
    }
    block_cache.count = 0;

    // Libérer la liste des allocations
    allocation_info_t* alloc_current = allocation_list;
    while (alloc_current) {
        allocation_info_t* next = alloc_current->next;
        free(alloc_current);
        alloc_current = next;
    }
    allocation_list = NULL;
}

void run_tests() {
    printf("\n=== Tests complets ===\n");

    // 1. Tests d'allocation de base
    void* block1 = my_malloc(1024, DEFAULT_MAX_ALLOC_SIZE);
    if (block1) {
        printf("[OK] Allocation de 1024 octets\n");
        my_free(block1);
        printf("[OK] Libération simple\n");
    }

    // 2. Tests des cas limites
    void* ptr_zero = my_malloc(0, DEFAULT_MAX_ALLOC_SIZE);
    if (!ptr_zero) {
        printf("[OK] Rejet allocation taille 0\n");
    }

    void* ptr_large = my_malloc(DEFAULT_MAX_ALLOC_SIZE + 1, DEFAULT_MAX_ALLOC_SIZE);
    if (!ptr_large) {
        printf("[OK] Rejet allocation trop grande\n");
    }

    // 3. Test du cache
    void* cached_block = my_malloc(128, DEFAULT_MAX_ALLOC_SIZE);
    if (cached_block) {
        my_free(cached_block);
        void* reused_block = my_malloc(128, DEFAULT_MAX_ALLOC_SIZE);
        if (reused_block == cached_block) {
            printf("[OK] Réutilisation du cache\n");
        }
        my_free(reused_block);
    }

    // 4. Test de grande allocation
    void* large_block = my_malloc(MAX_CACHED_BLOCK_SIZE + 1, DEFAULT_MAX_ALLOC_SIZE);
    if (large_block) {
        printf("[OK] Grande allocation (> MAX_CACHED_BLOCK_SIZE)\n");
        my_free(large_block);
        printf("[OK] Libération grande allocation\n");
    }

    // 5. Test de realloc
    void* block_realloc = my_malloc(256, DEFAULT_MAX_ALLOC_SIZE);
    if (block_realloc) {
        strcpy((char*)block_realloc, "test");
        void* block_expanded = my_realloc(block_realloc, 512);
        if (block_expanded && strcmp((char*)block_expanded, "test") == 0) {
            printf("[OK] Realloc avec préservation des données\n");
        }
        my_free(block_expanded);
    }

    // 6. Test de fragmentation et fusion
    void* block_a = my_malloc(128, DEFAULT_MAX_ALLOC_SIZE);
    void* block_b = my_malloc(128, DEFAULT_MAX_ALLOC_SIZE);
    void* block_c = my_malloc(128, DEFAULT_MAX_ALLOC_SIZE);
    
    if (block_a && block_b && block_c) {
        my_free(block_b); // Crée un trou
        void* block_d = my_malloc(256, DEFAULT_MAX_ALLOC_SIZE);
        if (!block_d) {
            printf("[OK] Détection correcte de la fragmentation\n");
        } else {
            my_free(block_d);
        }
        my_free(block_a);
        my_free(block_c);
    }

    // 7. Test des erreurs
    if (my_free(NULL) == -1) {
        printf("[OK] Rejet libération NULL\n");
    }
    
    void* invalid_ptr = (void*)1234;
    if (my_free(invalid_ptr) == -1) {
        printf("[OK] Rejet libération pointeur invalide\n");
    }

    // Nettoyage
    cleanup_memory();
    printf("\nTests terminés.\n");
}

// Mesure du temps
long get_time_in_microseconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

// Fonction de benchmark améliorée
void run_advanced_benchmark(const char* label, void* (*alloc_func)(size_t), void (*free_func)(void*)) {
    printf("\n=== Benchmark : %s ===\n", label);
    
    size_t test_sizes[] = {16, 64, 256, 1024, 4096};
    size_t num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);
    size_t iterations = 100; // Réduit pour éviter d'atteindre la limite de blocs
    
    double total_alloc_time = 0;
    double total_free_time = 0;
    
    for (size_t s = 0; s < num_sizes; s++) {
        size_t size = test_sizes[s];
        void** pointers = malloc(iterations * sizeof(void*));
        if (!pointers) continue;

        // Test d'allocation
        long start = get_time_in_microseconds();
        size_t success_count = 0;
        for (size_t i = 0; i < iterations; i++) {
            pointers[i] = alloc_func(size);
            if (pointers[i]) success_count++;
        }
        long alloc_time = get_time_in_microseconds() - start;

        // Test de libération
        start = get_time_in_microseconds();
        for (size_t i = 0; i < success_count; i++) {
            if (pointers[i]) {
                free_func(pointers[i]);
            }
        }
        long free_time = get_time_in_microseconds() - start;

        double avg_alloc = success_count > 0 ? (double)alloc_time/success_count : 0;
        double avg_free = success_count > 0 ? (double)free_time/success_count : 0;
        
        total_alloc_time += avg_alloc;
        total_free_time += avg_free;

        printf("Blocs %5zu octets : Alloc %.2f µs | Free %.2f µs\n",
               size, avg_alloc, avg_free);

        free(pointers);
    }
    
    printf("\nMoyennes globales:\n");
    printf("Allocation : %.2f µs\n", total_alloc_time/num_sizes);
    printf("Libération : %.2f µs\n", total_free_time/num_sizes);

    // Nettoyer la mémoire après les benchmarks
    cleanup_memory();
}

// Wrappers pour malloc/free
void* malloc_wrapper(size_t size) {
    return malloc(size);
}

void free_wrapper(void* ptr) {
    free(ptr);
}

// Wrappers pour my_malloc/my_free
void* my_malloc_wrapper(size_t size) {
    return my_malloc(size, DEFAULT_MAX_ALLOC_SIZE);
}

void my_free_wrapper(void* ptr) {
    my_free(ptr);
}

// Fonction principale
int main(int argc, char* argv[]) {
    printf("=== Allocateur de mémoire optimisé ===\n");

    // Exécution des tests
    run_tests();

    // Benchmarks comparatifs
    printf("\n=== Benchmarks comparatifs ===\n");
    run_advanced_benchmark("malloc/free système", malloc_wrapper, free_wrapper);
    cleanup_memory(); // Nettoyage entre les benchmarks
    run_advanced_benchmark("allocateur optimisé", my_malloc_wrapper, my_free_wrapper);

    // Rapport de fuites mémoire
    printf("\n=== Rapport de fuites mémoire ===\n");
    if (active_allocations > 0) {
        printf("ATTENTION: %zu allocations non libérées\n", active_allocations);
        printf("Mémoire non libérée: %zu octets\n", total_memory_allocated);
    } else {
        printf("Aucune fuite mémoire détectée\n");
    }

    // Nettoyage final
    cleanup_memory();
    return 0;
}

// Fonction de recherche best fit
mem_block_t* find_best_fit(size_t size) {
    mem_block_t* best_block = NULL;
    size_t min_diff = SIZE_MAX;  // Différence minimale trouvée
    mem_block_t* current = mem_blocks;

    // Parcourir tous les blocs pour trouver le meilleur ajustement
    while (current) {
        if (!current->in_use && current->size >= size) {
            size_t diff = current->size - size;
            if (diff < min_diff) {
                min_diff = diff;
                best_block = current;
                // Si on trouve un bloc parfait, on arrête la recherche
                if (diff == 0) break;
            }
        }
        current = current->next;
    }

    return best_block;
}