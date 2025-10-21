/**
 * LRU Cache (Least Recently Used)
 * 
 * Implementa un sistema de caché con capacidad máxima que elimina
 * los elementos menos usados recientemente cuando se alcanza el límite.
 * 
 * Complejidad:
 * - get(key): O(1)
 * - put(key, value): O(1)
 * - Espacio: O(capacity)
 * 
 * Estructura de datos: Combinación de Map + LinkedList
 * - Map: Para acceso O(1) a los nodos
 * - LinkedList (doubly): Para mantener orden de uso (más reciente al final)
 */

// Clase Node: representa cada elemento en la lista enlazada
class Node {
constructor(key, value) {
this.key = key;           // Clave del elemento almacenado
this.value = value;       // Valor del elemento almacenado
this.prev = null;         // Referencia al nodo anterior
this.next = null;         // Referencia al nodo siguiente
}
}

class LRUCache {
/**
 * Constructor del cache LRU
 * @param {number} capacity - Capacidad máxima del cache
 */
constructor(capacity) {
// Validar que la capacidad sea válida
if (capacity <= 0) {
    throw new Error('Capacity debe ser mayor a 0');
}

// Almacenar la capacidad máxima del cache
this.capacity = capacity;

// Map para almacenar referencias a los nodos por clave
// Permite acceso O(1): key -> Node
this.cache = new Map();

// Crear dos nodos centinela (dummy nodes) para simplificar la lógica
// head: nodo al inicio (menos usado recientemente está aquí)
this.head = new Node(0, 0);
// tail: nodo al final (más usado recientemente está aquí)
this.tail = new Node(0, 0);

// Conectar los nodos centinela entre sí
this.head.next = this.tail;  // head apunta a tail
this.tail.prev = this.head;  // tail apunta a head
}

/**
 * Obtiene un valor del cache
 * Si existe, lo marca como usado recientemente (lo mueve al final)
 * @param {string} key - Clave a buscar
 * @returns {any} Valor encontrado o -1 si no existe
 */
get(key) {
// Verificar si la clave existe en el cache
if (!this.cache.has(key)) {
    // No existe, retornar -1
    return -1;
}

// Obtener el nodo asociado a esta clave desde el Map
const node = this.cache.get(key);

// Mover el nodo al final de la lista (marcarlo como más usado recientemente)
this._moveToEnd(node);

// Retornar el valor almacenado en el nodo
return node.value;
}

/**
 * Almacena un valor en el cache
 * Si la clave ya existe, actualiza el valor y la marca como usada recientemente
 * Si la capacidad está llena, elimina el elemento menos usado
 * @param {string} key - Clave
 * @param {any} value - Valor a almacenar
 */
put(key, value) {
// CASO 1: La clave ya existe en el cache
if (this.cache.has(key)) {
    // Obtener el nodo existente
    const node = this.cache.get(key);
    
    // Actualizar el valor con el nuevo valor
    node.value = value;
    
    // Mover el nodo al final (marcarlo como más usado recientemente)
    this._moveToEnd(node);
    
    // Terminar la función
    return;
}

// CASO 2: Agregar una nueva clave (que no existe)

// Verificar si el cache ha alcanzado su capacidad máxima
if (this.cache.size >= this.capacity) {
    // El cache está lleno, necesitamos eliminar el elemento menos usado
    
    // El nodo menos usado es siempre el que viene después de head
    const lruNode = this.head.next;
    
    // Remover el nodo de la lista enlazada
    this._removeNode(lruNode);
    
    // Remover la clave del Map para liberar memoria
    this.cache.delete(lruNode.key);
}

// Crear un nuevo nodo con la clave y valor proporcionados
const newNode = new Node(key, value);

// Agregar la nueva clave al Map para acceso rápido
this.cache.set(key, newNode);

// Agregar el nuevo nodo al final de la lista (es el más usado recientemente)
this._addToEnd(newNode);
}

/**
 * MÉTODO AUXILIAR: Mueve un nodo al final de la lista
 * Esto marca el elemento como más usado recientemente
 * @private
 */
_moveToEnd(node) {
// Primero, remover el nodo de su posición actual
this._removeNode(node);

// Luego, agregarlo al final de la lista
this._addToEnd(node);
}

/**
 * MÉTODO AUXILIAR: Remueve un nodo de la lista enlazada
 * El nodo se desconecta manteniendo la lista conectada
 * @private
 */
_removeNode(node) {
// Obtener referencias al nodo anterior y siguiente
const prev = node.prev;
const next = node.next;

// Conectar el nodo anterior directamente con el nodo siguiente
// Saltando así el nodo que queremos remover
prev.next = next;

// Conectar el nodo siguiente hacia el nodo anterior
next.prev = prev;
}

/**
 * MÉTODO AUXILIAR: Agrega un nodo al final de la lista
 * El nuevo nodo se coloca justo antes del nodo tail (centinela final)
 * @private
 */
_addToEnd(node) {
// Obtener el nodo que está actualmente al final (justo antes de tail)
// node.prev apunta al nodo anterior al tail
node.prev = this.tail.prev;

// node.next apunta al tail (nodo centinela final)
node.next = this.tail;

// Actualizar el nodo que estaba al final para que apunte a este nuevo nodo
this.tail.prev.next = node;

// Actualizar tail para que apunte a este nuevo nodo como su anterior
this.tail.prev = node;
}

/**
 * Retorna el tamaño actual del cache
 */
size() {
// Retornar la cantidad de elementos almacenados en el Map
return this.cache.size;
}

/**
 * Retorna todas las claves en orden de uso
 * De menos reciente (izquierda) a más reciente (derecha)
 * Útil para debugging
 */
keys() {
// Array para almacenar las claves en orden
const result = [];

// Iniciar desde el primer nodo real (después del head centinela)
let current = this.head.next;

// Iterar hasta llegar al tail (nodo centinela final)
while (current !== this.tail) {
    // Agregar la clave del nodo actual al resultado
    result.push(current.key);
    
    // Mover al siguiente nodo
    current = current.next;
}

// Retornar el array de claves en orden
return result;
}
}

// ========================================
// CASOS DE PRUEBA
// ========================================

console.log('=== Test 1: Caso básico ===');
// Crear un cache con capacidad máxima de 3 elementos
const cache1 = new LRUCache(3);

// Agregar 3 elementos
cache1.put('a', 1);
cache1.put('b', 2);
cache1.put('c', 3);
console.log('Cache después de agregar a, b, c:', cache1.keys());

// Acceder a 'a' lo mueve al final (más usado recientemente)
console.log('get("a"):', cache1.get('a')); // Retorna 1
console.log('Cache después de get("a"):', cache1.keys());

// Agregar 'd' cuando está lleno: elimina 'b' (menos usado)
cache1.put('d', 4);
console.log('Cache después de put("d", 4):', cache1.keys());

// Intentar acceder a 'b' que fue eliminado
console.log('get("b"):', cache1.get('b')); // Retorna -1
console.log();

console.log('=== Test 2: Actualización de valor existente ===');
// Crear cache con capacidad 2
const cache2 = new LRUCache(2);

// Agregar 2 elementos
cache2.put('x', 10);
cache2.put('y', 20);
console.log('Cache inicial:', cache2.keys());

// Actualizar 'x' con nuevo valor y moverlo al final
cache2.put('x', 100);
console.log('Cache después de actualizar x:', cache2.keys());

// Agregar 'z' cuando está lleno: elimina 'y' (menos usado)
cache2.put('z', 30);
console.log('Cache después de put("z", 30):', cache2.keys());
console.log();

console.log('=== Test 3: Capacidad de 1 ===');
// Crear cache con capacidad mínima de 1
const cache3 = new LRUCache(1);

// Agregar primer elemento
cache3.put('a', 1);
console.log('Cache con capacidad 1:', cache3.keys());

// Agregar segundo elemento: elimina 'a'
cache3.put('b', 2);
console.log('Después de agregar b:', cache3.keys());

// Verificar que 'a' fue eliminado
console.log('get("a"):', cache3.get('a')); // -1
console.log('get("b"):', cache3.get('b')); // 2
console.log();

console.log('=== Test 4: Múltiples gets (sin cambiar orden) ===');
// Crear cache con capacidad 3
const cache4 = new LRUCache(3);

// Agregar 3 elementos
cache4.put('a', 1);
cache4.put('b', 2);
cache4.put('c', 3);
console.log('Cache inicial:', cache4.keys());

// Acceder a 'a' varias veces (cada acceso lo mueve al final)
cache4.get('a');
cache4.get('a');
// Acceder a 'b' una vez
cache4.get('b');
console.log('Orden después de gets:', cache4.keys());

// Agregar 'd': debe eliminar 'c' (es el menos usado)
cache4.put('d', 4);
console.log('Después de agregar d:', cache4.keys());
console.log();

console.log('=== Test 5: Estrés - muchos elementos ===');
// Crear cache con capacidad 5
const cache5 = new LRUCache(5);

// Agregar 10 elementos cuando la capacidad es solo 5
for (let i = 1; i <= 10; i++) {
cache5.put(`key${i}`, i * 10);
}

// El cache solo debe contener los últimos 5 elementos (key6 a key10)
console.log('Cache después de 10 inserciones (capacidad 5):', cache5.keys());
console.log('Tamaño:', cache5.size());