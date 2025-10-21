/**
 * ALGORITMO 2: Análisis de Patrones - Detección de Actividad Sospechosa
 * 
 * Detecta patrones sospechosos en logs de acceso a una API:
 * 1. IPs con exceso de requests por minuto
 * 2. Patrones de fuerza bruta (múltiples fallos de login)
 * 3. Acceso masivo a endpoints sensibles
 * 4. Comportamiento anómalo por User-Agent
 * 
 * Complejidad: O(n log n) - n es cantidad de logs
 * Espacio: O(n)
 */

function detectarActividadSospechosa(logs, config) {
// ========================================
// PASO 1: INICIALIZAR ESTRUCTURAS DE DATOS
// ========================================

// Objeto para almacenar ips sospechosas encontradas
const ips_sospechosas = [];

// Objeto para almacenar intentos de fuerza bruta
const ataques_fuerza_bruta = [];

// Objeto para almacenar endpoints bajo ataque
const endpoints_bajo_ataque = [];

// Objeto para almacenar anomalías detectadas
const anomalias_detectadas = [];

// Contador total de eventos sospechosos
let total_eventos_sospechosos = 0;

// ========================================
// PASO 2: CREAR MAPAS PARA ANÁLISIS
// ========================================

// Mapa para contar requests por IP: { "192.168.1.1": { timestamps: [...], count: 5 } }
const requestsPorIP = new Map();

// Mapa para contar fallos de login por IP: { "192.168.1.1": { count: 3, timestamps: [...] } }
const fallosLoginPorIP = new Map();

// Mapa para contar accesos a endpoints sensibles: { "/api/login": { count: 10, ips: [...] } }
const accesosEndpointSensible = new Map();

// Mapa para contar User-Agents por IP: { "192.168.1.1": { "Mozilla": 5, "curl": 20 } }
const userAgentsPorIP = new Map();

// Mapa para almacenar tiempo de respuesta por IP (para detectar anomalías)
const tiemposRespuestaPorIP = new Map();

// ========================================
// PASO 3: PROCESAR CADA LOG
// ========================================

// Iterar sobre todos los logs
logs.forEach((log) => {
// Extraer información del log
const { ip, endpoint, timestamp, status, user_agent, response_time } = log;

// --- ANÁLISIS 1: Contar requests por IP ---
// Verificar si la IP ya existe en el mapa
if (!requestsPorIP.has(ip)) {
    // Si no existe, crear nueva entrada con array vacío de timestamps
    requestsPorIP.set(ip, { timestamps: [], count: 0 });
}

// Agregar el timestamp del log actual
requestsPorIP.get(ip).timestamps.push(timestamp);
// Incrementar contador de requests
requestsPorIP.get(ip).count++;

// --- ANÁLISIS 2: Detectar fallos de login (status 401 o 403) ---
// Verificar si es un endpoint de login y falló la autenticación
if (config.suspicious_endpoints.includes(endpoint) && (status === 401 || status === 403)) {
    // Verificar si la IP ya tiene fallos registrados
    if (!fallosLoginPorIP.has(ip)) {
    // Si no existe, crear nueva entrada
    fallosLoginPorIP.set(ip, { count: 0, timestamps: [] });
    }
    
    // Incrementar contador de fallos de login
    fallosLoginPorIP.get(ip).count++;
    // Agregar timestamp del fallo
    fallosLoginPorIP.get(ip).timestamps.push(timestamp);
}

// --- ANÁLISIS 3: Contar accesos a endpoints sensibles ---
// Verificar si el endpoint actual es sensible (configurado)
if (config.suspicious_endpoints.includes(endpoint)) {
    // Verificar si el endpoint ya existe en el mapa
    if (!accesosEndpointSensible.has(endpoint)) {
    // Si no existe, crear nueva entrada
    accesosEndpointSensible.set(endpoint, { count: 0, ips: [] });
    }
    
    // Incrementar contador de accesos al endpoint
    accesosEndpointSensible.get(endpoint).count++;
    // Agregar la IP si es la primera vez que accede
    accesosEndpointSensible.get(endpoint).ips.push(ip);
}

// --- ANÁLISIS 4: Rastrear User-Agents por IP (para detectar anomalías) ---
// Verificar si la IP ya tiene User-Agents rastreados
if (!userAgentsPorIP.has(ip)) {
    // Si no existe, crear nuevo mapa de User-Agents
    userAgentsPorIP.set(ip, {});
}

// Obtener el mapa de User-Agents para esta IP
const ua_map = userAgentsPorIP.get(ip);

// Contar cuántas veces aparece este User-Agent
if (!ua_map[user_agent]) {
    ua_map[user_agent] = 0;
}
ua_map[user_agent]++;

// --- ANÁLISIS 5: Almacenar tiempos de respuesta por IP ---
// Verificar si la IP ya tiene tiempos de respuesta
if (!tiemposRespuestaPorIP.has(ip)) {
    // Si no existe, crear array vacío de tiempos
    tiemposRespuestaPorIP.set(ip, []);
}

// Agregar el tiempo de respuesta actual
tiemposRespuestaPorIP.get(ip).push(response_time);
});

// ========================================
// PASO 4: DETECTAR IPS SOSPECHOSAS
// ========================================

// Iterar sobre cada IP y sus requests
requestsPorIP.forEach((data, ip) => {
// data contiene { timestamps: [...], count: N }
const { timestamps, count } = data;

// --- BÚSQUEDA 1: Exceso de requests por minuto ---

// Ordenar los timestamps para análisis de ventanas deslizantes
// Esto permite buscar períodos de tiempo específicos
timestamps.sort((a, b) => a - b);

// Iterar sobre cada timestamp para ver si hay exceso de requests en una ventana de tiempo
for (let i = 0; i < timestamps.length; i++) {
    // Obtener el timestamp actual
    const current_time = timestamps[i];
    
    // Definir la ventana de tiempo (desde current_time hasta current_time + time_window)
    const window_start = current_time;
    const window_end = current_time + config.time_window;
    
    // Contar cuántos requests hay dentro de esta ventana
    let requests_in_window = 0;
    for (let j = i; j < timestamps.length; j++) {
    // Si el timestamp está dentro de la ventana, contar
    if (timestamps[j] <= window_end) {
        requests_in_window++;
    } else {
        // Los timestamps están ordenados, así que podemos parar
        break;
    }
    }
    
    // Convertir ventana de tiempo a minutos para comparación
    const window_minutes = config.time_window / 60000;
    
    // Calcular requests por minuto
    const requests_per_minute = requests_in_window / window_minutes;
    
    // Verificar si excede el límite configurado
    if (requests_per_minute > config.max_requests_per_minute) {
    // Agregar a IPs sospechosas si no está ya registrada
    if (!ips_sospechosas.find(item => item.ip === ip)) {
        ips_sospechosas.push({
        ip: ip,
        razon: 'Exceso de requests por minuto',
        requests_detectados: requests_per_minute.toFixed(2),
        limite_permitido: config.max_requests_per_minute,
        ventana_minutos: window_minutes
        });
        total_eventos_sospechosos++;
    }
    // Salir del loop ya que encontramos una violación
    break;
    }
}
});

// ========================================
// PASO 5: DETECTAR ATAQUES DE FUERZA BRUTA
// ========================================

// Iterar sobre cada IP y sus intentos fallidos de login
fallosLoginPorIP.forEach((data, ip) => {
// data contiene { count: N, timestamps: [...] }
const { count, timestamps } = data;

// Verificar si la cantidad de fallos excede el límite configurado
if (count > config.max_failed_logins) {
    // Agregar a ataques de fuerza bruta
    ataques_fuerza_bruta.push({
    ip: ip,
    tipo_ataque: 'Fuerza Bruta en Login',
    intentos_fallidos: count,
    limite_permitido: config.max_failed_logins,
    timestamps_intentos: timestamps,
    primera_tentativa: new Date(timestamps[0]).toISOString(),
    ultima_tentativa: new Date(timestamps[timestamps.length - 1]).toISOString()
    });
    total_eventos_sospechosos++;
}
});

// ========================================
// PASO 6: DETECTAR ENDPOINTS BAJO ATAQUE
// ========================================

// Iterar sobre cada endpoint sensible
accesosEndpointSensible.forEach((data, endpoint) => {
// data contiene { count: N, ips: [...] }
const { count, ips } = data;

// Obtener cantidad de IPs únicas que intentaron acceder
const unique_ips = new Set(ips).size;

// Definir umbral de acceso masivo (más de 10 IPs diferentes)
const umbral_ips = 10;

// Verificar si hay acceso masivo desde múltiples IPs
if (unique_ips > umbral_ips) {
    endpoints_bajo_ataque.push({
    endpoint: endpoint,
    total_accesos: count,
    ips_unicas: unique_ips,
    descripcion: 'Acceso masivo desde múltiples IPs'
    });
    total_eventos_sospechosos++;
}
});

// ========================================
// PASO 7: DETECTAR ANOMALÍAS POR USER-AGENT
// ========================================

// Iterar sobre cada IP y sus User-Agents
userAgentsPorIP.forEach((ua_map, ip) => {
// ua_map es un objeto: { "Mozilla": 5, "curl": 20, ... }

// Obtener los User-Agents únicos para esta IP
const user_agents = Object.keys(ua_map);

// Obtener las frecuencias de cada User-Agent
const frecuencias = Object.values(ua_map);

// Verificar si hay mucha variación en User-Agents (anomalía)
// Si una IP tiene más de 5 User-Agents diferentes = comportamiento anómalo
if (user_agents.length > 5) {
    // Calcular estadísticas
    const total_requests = frecuencias.reduce((a, b) => a + b, 0);
    const user_agent_mas_comun = user_agents[
    frecuencias.indexOf(Math.max(...frecuencias))
    ];
    
    anomalias_detectadas.push({
    ip: ip,
    tipo_anomalia: 'Múltiples User-Agents',
    cantidad_user_agents: user_agents.length,
    user_agent_mas_comun: user_agent_mas_comun,
    total_requests_desde_ip: total_requests,
    detalle: 'Comportamiento sospechoso: demasiados User-Agents diferentes'
    });
    total_eventos_sospechosos++;
}
});

// ========================================
// PASO 8: DETECTAR ANOMALÍAS EN TIEMPOS DE RESPUESTA
// ========================================

// Iterar sobre cada IP y sus tiempos de respuesta
tiemposRespuestaPorIP.forEach((tiempos, ip) => {
// tiempos es un array de valores de response_time

// Calcular promedio de tiempos de respuesta
const promedio = tiempos.reduce((a, b) => a + b, 0) / tiempos.length;

// Calcular desviación estándar (varianza en tiempos)
const varianza = tiempos.reduce((sum, t) => sum + Math.pow(t - promedio, 2), 0) / tiempos.length;
const desv_estandar = Math.sqrt(varianza);

// Si la desviación estándar es muy alta = comportamiento inconsistente (posible anomalía)
// Umbrales típicos: desviación > promedio * 1.5
if (desv_estandar > promedio * 1.5) {
    anomalias_detectadas.push({
    ip: ip,
    tipo_anomalia: 'Tiempos de respuesta irregulares',
    tiempo_promedio_ms: promedio.toFixed(2),
    desviacion_estandar_ms: desv_estandar.toFixed(2),
    detalle: 'Comportamiento inconsistente en tiempos de respuesta'
    });
    total_eventos_sospechosos++;
}
});

// ========================================
// PASO 9: RETORNAR RESULTADO
// ========================================

// Retornar objeto con todos los hallazgos
return {
ips_sospechosas: ips_sospechosas,           // IPs con exceso de requests
ataques_fuerza_bruta: ataques_fuerza_bruta, // Intentos de fuerza bruta detectados
endpoints_bajo_ataque: endpoints_bajo_ataque, // Endpoints con acceso masivo
anomalias_detectadas: anomalias_detectadas, // Otras anomalías
total_eventos_sospechosos: total_eventos_sospechosos // Total de eventos
};
}

// ========================================
// CASOS DE PRUEBA
// ========================================

// --- TEST 1: Caso básico con IP sospechosa ---
console.log('=== TEST 1: IP con exceso de requests ===');

// Crear logs de prueba: una IP hace 15 requests en 1 minuto
const logs1 = [];
for (let i = 0; i < 15; i++) {
logs1.push({
ip: '192.168.1.100',
endpoint: '/api/users',
timestamp: Date.now() + (i * 4000), // 4 segundos entre cada request
status: 200,
user_agent: 'Mozilla/5.0',
response_time: 100
});
}

// Configuración de detección
const config1 = {
max_requests_per_minute: 60,
max_failed_logins: 5,
suspicious_endpoints: ['/api/login', '/api/admin'],
time_window: 60000 // 1 minuto en ms
};

// Ejecutar detección
const resultado1 = detectarActividadSospechosa(logs1, config1);
console.log('Resultado:', JSON.stringify(resultado1, null, 2));
console.log();

// --- TEST 2: Fuerza bruta en login ---
console.log('=== TEST 2: Ataque de fuerza bruta ===');

// Crear logs: una IP intenta 10 veces el login y falla
const logs2 = [];
for (let i = 0; i < 10; i++) {
logs2.push({
ip: '192.168.1.50',
endpoint: '/api/login',
timestamp: Date.now() + (i * 1000),
status: 401, // Fallo de autenticación
user_agent: 'Mozilla/5.0',
response_time: 150
});
}

const config2 = {
max_requests_per_minute: 60,
max_failed_logins: 5, // Máximo 5 fallos permitidos
suspicious_endpoints: ['/api/login', '/api/admin'],
time_window: 300000 // 5 minutos
};

const resultado2 = detectarActividadSospechosa(logs2, config2);
console.log('Ataques de fuerza bruta encontrados:', resultado2.ataques_fuerza_bruta);
console.log();

// --- TEST 3: Acceso masivo a endpoints sensibles ---
console.log('=== TEST 3: Acceso masivo a endpoint sensible ===');

// Crear logs: 15 IPs diferentes intentan acceder a /api/admin
const logs3 = [];
for (let i = 0; i < 15; i++) {
logs3.push({
ip: `192.168.1.${i + 100}`, // Diferentes IPs
endpoint: '/api/admin',
timestamp: Date.now() + (i * 100),
status: 403, // Acceso denegado
user_agent: 'Mozilla/5.0',
response_time: 100
});
}

const config3 = {
max_requests_per_minute: 100,
max_failed_logins: 5,
suspicious_endpoints: ['/api/login', '/api/admin'],
time_window: 300000
};

const resultado3 = detectarActividadSospechosa(logs3, config3);
console.log('Endpoints bajo ataque:', resultado3.endpoints_bajo_ataque);
console.log();

// --- TEST 4: Anomalía por múltiples User-Agents ---
console.log('=== TEST 4: Múltiples User-Agents (comportamiento anómalo) ===');

// Crear logs: una IP accede con 7 User-Agents diferentes
const logs4 = [];
const user_agents = [
'Mozilla/5.0 (Windows)',
'curl/7.64.1',
'python-requests/2.25.1',
'Postman/9.0',
'insomnia/2021.7.2',
'wget/1.20.3',
'java/1.8.0'
];

user_agents.forEach((ua, i) => {
logs4.push({
ip: '192.168.1.200',
endpoint: '/api/users',
timestamp: Date.now() + (i * 1000),
status: 200,
user_agent: ua,
response_time: 100
});
});

const config4 = {
max_requests_per_minute: 60,
max_failed_logins: 5,
suspicious_endpoints: ['/api/login', '/api/admin'],
time_window: 300000
};

const resultado4 = detectarActividadSospechosa(logs4, config4);
console.log('Anomalías detectadas:', resultado4.anomalias_detectadas);
console.log('Total eventos sospechosos:', resultado4.total_eventos_sospechosos);
console.log();

// --- TEST 5: Caso combinado (múltiples amenazas) ---
console.log('=== TEST 5: Múltiples amenazas simultáneamente ===');

const logs5 = [
// IP 1: Mucho traffic
...Array.from({length: 20}, (_, i) => ({
ip: '10.0.0.1',
endpoint: '/api/users',
timestamp: Date.now() + (i * 2000),
status: 200,
user_agent: 'Mozilla/5.0',
response_time: 100 + Math.random() * 50
})),

// IP 2: Intentos de fuerza bruta
...Array.from({length: 8}, (_, i) => ({
ip: '10.0.0.2',
endpoint: '/api/login',
timestamp: Date.now() + (i * 500),
status: 401,
user_agent: 'Mozilla/5.0',
response_time: 200
}))
];

const config5 = {
max_requests_per_minute: 60,
max_failed_logins: 5,
suspicious_endpoints: ['/api/login', '/api/admin'],
time_window: 60000
};

const resultado5 = detectarActividadSospechosa(logs5, config5);
console.log('Reporte completo:', {
ips_sospechosas: resultado5.ips_sospechosas.length,
ataques_fuerza_bruta: resultado5.ataques_fuerza_bruta.length,
endpoints_bajo_ataque: resultado5.endpoints_bajo_ataque.length,
anomalias: resultado5.anomalias_detectadas.length,
total: resultado5.total_eventos_sospechosos
});