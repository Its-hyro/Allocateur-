#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

// Limite d'allocation par défaut (1 Mo, ajustable si besoin)
#define DEFAULT_MAX_ALLOC_SIZE (sysconf(_SC_PAGESIZE) * 1024)

// Structure de bloc mémoire
typedef struct mem_block_t {
    void* ptr;                 // Pointeur vers le début du bloc
    size_t size;               // Taille du bloc en octets
    int in_use;                // Indicateur d'utilisation (1 = utilisé, 0 = libre)
    struct mem_block_t* next;  // Pointeur vers le bloc suivant (liste chaînée)
} mem_block_t;

mem_block_t* mem_blocks = NULL; // Liste des blocs mémoire
size_t allocated_blocks = 0;    // Compteur des blocs alloués

// Fonction pour créer un bloc mémoire
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

// Ajout d'un bloc dans la liste chaînée
void add_block(mem_block_t* block) {
    if (!mem_blocks) {
        mem_blocks = block;
    } else {
        mem_block_t* current = mem_blocks;
        while (current->next) {
            current = current->next;
        }
        current->next = block;
    }
    allocated_blocks++;
}

// Fusion des blocs libres adjacents
void coalesce_free_blocks() {
    mem_block_t* current = mem_blocks;
    while (current && current->next) {
        if (!current->in_use && !current->next->in_use) {
            current->size += current->next->size;
            mem_block_t* temp = current->next;
            current->next = temp->next;
            free(temp);
            allocated_blocks--;
        } else {
            current = current->next;
        }
    }
}

// Fonction d'allocation personnalisée
void* my_malloc(size_t size, size_t max_alloc_size) {
    if (size == 0 || size > max_alloc_size) {
        errno = EINVAL;
        return NULL;
    }

    // Recherche d'un bloc libre réutilisable
    mem_block_t* current = mem_blocks;
    while (current) {
        if (!current->in_use && current->size >= size) {
            if (current->size > size) {
                mem_block_t* new_block = create_block((char*)current->ptr + size, current->size - size, 0);
                if (!new_block) return NULL;
                new_block->next = current->next;
                current->next = new_block;
                current->size = size;
                allocated_blocks++;
            }
            current->in_use = 1;
            return current->ptr;
        }
        current = current->next;
    }

    // Aucun bloc libre trouvé, allouer un nouveau bloc
    void* new_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_ptr == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    mem_block_t* new_block = create_block(new_ptr, size, 1);
    if (!new_block) {
        munmap(new_ptr, size);
        return NULL;
    }

    add_block(new_block);
    return new_ptr;
}

// Fonction pour libérer un bloc
int my_free(void* ptr) {
    if (!ptr) {
        errno = EINVAL;
        return -1;
    }

    mem_block_t* current = mem_blocks;
    while (current) {
        if (current->ptr == ptr) {
            if (!current->in_use) {
                errno = EINVAL;
                return -1;
            }
            current->in_use = 0;
            coalesce_free_blocks();
            return 0;
        }
        current = current->next;
    }

    errno = ENOENT;
    return -1;
}

// Réallocation personnalisée
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

// Tests unitaires
void assert_test(int condition, const char* message) {
    if (condition) {
        printf("[OK] %s\n", message);
    } else {
        printf("[FAIL] %s\n", message);
        exit(EXIT_FAILURE);
    }
}

void run_tests() {
    printf("=== Début des tests ===\n");

    // Test d'allocation simple
    void* block1 = my_malloc(1024, DEFAULT_MAX_ALLOC_SIZE);
    assert_test(block1 != NULL, "Allocation simple réussie");
    assert_test(my_free(block1) == 0, "Libération simple réussie");

    // Cas limites
    assert_test(my_malloc(0, DEFAULT_MAX_ALLOC_SIZE) == NULL, "Allocation de 0 échoue");
    assert_test(my_malloc(DEFAULT_MAX_ALLOC_SIZE + 1, DEFAULT_MAX_ALLOC_SIZE) == NULL, "Dépassement de limite échoue");

    // Réutilisation et fragmentation
    void* block2 = my_malloc(512, DEFAULT_MAX_ALLOC_SIZE);
    void* block3 = my_malloc(1024, DEFAULT_MAX_ALLOC_SIZE);
    assert_test(block2 != NULL && block3 != NULL, "Deux allocations réussies");
    assert_test(my_free(block2) == 0, "Libération réussie");
    void* block4 = my_malloc(256, DEFAULT_MAX_ALLOC_SIZE);
    assert_test(block4 != NULL, "Réutilisation réussie");

    // Réallocation
    void* block5 = my_malloc(512, DEFAULT_MAX_ALLOC_SIZE);
    block5 = my_realloc(block5, 1024);
    assert_test(block5 != NULL, "Réallocation réussie");
    assert_test(my_free(block5) == 0, "Libération après réallocation réussie");

    printf("Tous les tests ont été passés avec succès !\n");
}

// Mesure du temps en microsecondes
long get_time_in_microseconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

// Fonction générique de benchmark
void run_benchmark(const char* label, void* (*alloc_func)(size_t), void (*free_func)(void*), size_t iterations, size_t size) {
    void** pointers = (void**)malloc(iterations * sizeof(void*));
    if (!pointers) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Mesurer le temps pour les allocations
    long start_alloc = get_time_in_microseconds();
    for (size_t i = 0; i < iterations; i++) {
        pointers[i] = alloc_func(size);
        if (!pointers[i]) {
            fprintf(stderr, "Allocation échouée lors de l'itération %zu\n", i);
            exit(EXIT_FAILURE);
        }
    }
    long end_alloc = get_time_in_microseconds();

    // Mesurer le temps pour les libérations
    long start_free = get_time_in_microseconds();
    for (size_t i = 0; i < iterations; i++) {
        free_func(pointers[i]);
    }
    long end_free = get_time_in_microseconds();

    free(pointers);

    // Afficher les résultats
    printf("%s:\n", label);
    printf("  Temps d'allocation : %ld µs\n", end_alloc - start_alloc); 
    printf("  Temps de libération : %ld µs\n", end_free - start_free);
    printf("  Temps total : %ld µs\n", (end_alloc - start_alloc) + (end_free - start_free));
    printf("-------------------------\n");
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
    printf("=== Tests et Benchmark ===\n");

    // Lancer les tests unitaires
    run_tests();

    // Paramètres de benchmark
    size_t iterations = (argc > 1) ? strtoul(argv[1], NULL, 10) : 100000; // Nombre d'itérations
    size_t size = (argc > 2) ? strtoul(argv[2], NULL, 10) : 64;           // Taille d'allocation

    printf("\n=== Benchmark ===\n");
    printf("Nombre d'itérations : %zu, Taille d'allocation : %zu octets\n", iterations, size);
    printf("-------------------------\n");

    // Benchmark pour malloc/free
    run_benchmark("malloc/free", malloc_wrapper, free_wrapper, iterations, size);

    // Benchmark pour my_malloc/my_free
    run_benchmark("my_malloc/my_free", my_malloc_wrapper, my_free_wrapper, iterations, size);

    return 0;


}