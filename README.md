# Algoritmo 1: LRU Cache

## Descripción
Implementación de un sistema de caché LRU (Least Recently Used) que mantiene un tamaño máximo y elimina elementos no usados recientemente.

## Complejidad
- **Temporal**: O(1) para operaciones get() y put()
- **Espacial**: O(capacity)

## Estructura de Datos
- Map para acceso O(1)
- LinkedList doblemente enlazada para mantener orden de uso

## Casos de Prueba
✅ Caso básico con eliminación por capacidad
✅ Actualización de valores existentes
✅ Cache con capacidad mínima (1)
✅ Múltiples accesos
✅ Test de estrés

# Algoritmo 2: Detección de Actividad Sospechosa

## Descripción
Sistema de análisis de logs de acceso a una API para detectar patrones sospechosos, ataques de fuerza bruta y comportamiento anómalo.

## Complejidad
- **Temporal**: O(n log n)
- **Espacial**: O(n)
  
## Estructura de Datos
- Map para agregación de datos por IP
- Arrays con ventanas deslizantes para análisis temporal
- Sets para conteo de elementos únicos

## Casos de Prueba
✅ IP con exceso de requests por minuto
✅ Ataque de fuerza bruta con múltiples fallos
✅ Acceso masivo a endpoints sensibles
✅ Múltiples User-Agents (comportamiento anómalo)
✅ Caso combinado con múltiples amenazas
