# Projet Allocateur de Mémoire

## 1. Instructions de Compilation et d'Exécution

### Compilation
```bash
# Compilation de l'allocateur de base
gcc -Wall -Wextra -o allocateur allocateur.c

# Compilation de l'allocateur avec cache
gcc -Wall -Wextra -o allocateur_cache allocateur_avec_cache.c

# Compilation de l'allocateur optimisé
gcc -Wall -Wextra -o allocateur2 allocateur2.c
```

### Exécution
```bash
# Exécution des tests et benchmarks
./allocateur2 [nombre_iterations] [taille_allocation]

# Exemple avec 100000 itérations et des blocs de 64 octets
./allocateur2 100000 64
```

## 2. Explication des Choix d'Implémentation

### Structure de Base
```c
typedef struct mem_block_t {
    void* ptr;                 // Pointeur vers le bloc de mémoire
    size_t size;              // Taille du bloc
    int in_use;               // État d'utilisation
    struct mem_block_t* next; // Bloc suivant
} mem_block_t;
```

Cette structure a été choisie pour sa simplicité et son efficacité. En utilisant une liste chaînée, nous pouvons facilement gérer les blocs de mémoire alloués et libres. Chaque bloc contient les informations essentielles pour la gestion de la mémoire, ce qui facilite le débogage et minimise l'overhead.

### Système de Cache
```c
#define CACHE_MAX_SIZE 10
static mem_block_t* free_cache[CACHE_MAX_SIZE];
```

L'idée derrière l'implémentation d'un cache était de réduire les appels système coûteux à `mmap` et `munmap`. En réutilisant les blocs libérés, nous pouvons améliorer considérablement les performances, en particulier pour les petites allocations fréquentes. Le cache permet une réutilisation rapide des blocs, ce qui est crucial pour les applications nécessitant des allocations dynamiques fréquentes.

### Alignement Mémoire
```c
#define ALIGNMENT 16
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
```

L'alignement des blocs de mémoire est une optimisation qui m'a semblé importante. En alignant les blocs sur 16 bytes, nous optimisons les performances d'accès mémoire et assurons la compatibilité avec différentes architectures. Cela réduit également la fragmentation interne, ce qui est essentiel pour maintenir une utilisation efficace de la mémoire.

## 3. Liste Des Optimisations

### Recyclage des Blocs Libérés

L'une des premières optimisations que j'ai implémentées a été le recyclage des blocs libérés. En créant un cache pour ces blocs, j'ai pu réduire le nombre d'appels à `mmap`, ce qui a amélioré les performances. elle est utile pour les petites allocations, où le coût des appels système peut être prohibitif.

### Coalescence des Blocs Libres
```c
void coalesce_free_blocks() {
    while (current && current->next) {
        if (!current->in_use && !current->next->in_use) {
            // Fusion des blocs adjacents
            current->size += current->next->size;
            current->next = current->next->next;
        }
    }
}
```

La coalescence des blocs libres sert à réduire la fragmentation externe. En fusionnant les blocs adjacents libres, nous pouvons libérer de plus grands blocs de mémoire, ce qui est pratique pour les allocations de grande taille. C'est pour moi l'amélioration la plus importante de l'allocateur (j'en ai chier).

### Best Fit
```c
mem_block_t* find_best_fit(size_t size) {
    mem_block_t* best = NULL;
    size_t min_diff = SIZE_MAX;
    // Recherche du bloc le plus adapté
}
```

L'algorithme Best Fit optimise l'utilisation de la mémoire. En cherchant le bloc libre le plus proche de la taille demandée, nous réduisons le gaspillage et minimisons la fragmentation interne. Cela a permis d'améliorer l'efficacité de l'allocateur, en particulier pour les allocations de taille moyenne.

### Alignement des Blocs

L'alignement des blocs sur 16 bytes a amélioré les performances d'accès mémoire. Cette optimisation assure que les blocs sont alignés de manière optimale pour les architectures modernes, ce qui réduit les cycles de CPU nécessaires pour accéder à la mémoire.

### Détection des Fuites Mémoire
```c
typedef struct allocation_info {
    void* ptr;
    size_t size;
    const char* file;
    int line;
} allocation_info_t;
```

La détection des fuites mémoire m'a donné envie de casser mon mac un nombre incalculable de fois (je n'ai pas installé valgrind donc cetait chiant). En traçant chaque allocation, nous pouvons identifier les fuites potentielles et faciliter le débogage. Cette fonctionnalité a été intégrée pour assurer la fiabilité et la robustesse de l'allocateur et surtout pour me réconforter que je ne suis pas un développeur de merde (spoiler : je suis un développeur de merde).

## 4. Résultats des Benchmarks

### Tests de Performance

1. **Petites Allocations (16-64 bytes)**
   - Version de base : 2.5x plus lent que malloc
   - Avec cache : 1.2x plus lent que malloc
   - Version finale : ~1.0x malloc (performances similaires)

2. **Allocations Moyennes (256-1024 bytes)**
   - Réduction de la fragmentation : 30%
   - Temps moyen : 1.5x malloc

3. **Grandes Allocations (>4KB)**
   - Performances similaires à malloc
   - Overhead négligeable

### Impact des Optimisations
- Cache : Amélioration de 40-60% des performances pour les petites allocations
- Coalescence : Réduction de 30% de la fragmentation
- Best Fit : Réduction de 20% du gaspillage mémoire

Les benchmarks ont été réalisés avec 100 000 itérations sur différentes tailles d'allocation, comparant systématiquement les performances avec l'allocateur système (malloc/free). Ces résultats montrent que les optimisations ont permis d'atteindre des performances proches de celles de l'allocateur système (si seulement), tout en offrant une flexibilité et une personnalisation accrues. Le projet a été sympa a faire je me suis bien amusé, je pense que je pourrais faire mieux mais (il est 22H) mes connaissances en C sont assez limitées a cause de mon cursus qui jusqu'à present etait de la physique (et oui je suis un développeur de merde je cherche juste des excuses). 


### Sources

https://man7.org/linux/man-pages/man3/malloc.3.html
https://www.geeksforgeeks.org/
dynamic-memory-allocation-in-c-using-malloc-calloc-free-and-realloc/?ref=header_outind
https://github.com/memkind/memkind
https://github.com/google/tcmalloc
https://www.tutorialspoint.com/data_structures_algorithms/linked_list_algorithms.htm
https://en.wikipedia.org/wiki/Memory_management
https://medium.com/software-design/
why-software-developers-should-care-about-cpu-caches-8da04355bb8a
https://medium.com/@azole/cache-memories-part-a-51fe5927e1e0
https://cs.stackexchange.com/search?q=caching+techniques
https://en.wikipedia.org/wiki/Data_structure_alignment
https://www.geeksforgeeks.org (en general pour les questions)
https://www.youtube.com/watch?v=CulF4YQt6zA

Je n'ai pas mis toutes les videos que j'ai regardées pour cet allocateur mais le dernier lien ma bien aidé pour la comprehension global d'un allocateur.
