# Base ESP32 — WiFi + HTTP Client + RFID RC522

Proyecto base para ESP32 usando **ESP-IDF**. Implementa conexión WiFi en modo estación, cliente HTTP para comunicarse con un servidor, y soporte para el módulo RFID RC522. Diseñado como plantilla reutilizable para proyectos IoT.

---

## Características

- Conexión WiFi con reintentos automáticos (hasta 5 por defecto)
- Cliente HTTP/HTTPS configurable
- Integración con módulo RFID **RC522** (lectura de tarjetas)
- Configuración centralizada por `menuconfig` (sin hardcodear credenciales)
- Arquitectura modular con componente `coms` separado del `main`

---

## Requisitos

| Requisito | Versión |
|---|---|
| ESP-IDF | v5.x recomendado |
| Toolchain | xtensa-esp32 |
| Hardware | ESP32 (cualquier variante) |
| Módulo RFID | RC522 (opcional) |

> Instalar ESP-IDF: [https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/)

---

## Estructura del proyecto

```
base-esp32-wifi/
├── main/
│   ├── main.c               # Punto de entrada: inicializa WiFi y RFID
│   └── CMakeLists.txt
├── coms/                    # Componente de comunicaciones
│   ├── wifi.c               # Lógica de conexión WiFi (station mode)
│   ├── http-req.c           # Cliente HTTP (en desarrollo)
│   ├── includes/            # Headers del componente
│   ├── Kconfig.projbuild    # Variables de configuración (menuconfig)
│   └── CMakeLists.txt
├── esp-idf-rc522-master/    # Componente externo para módulo RFID RC522
├── CMakeLists.txt           # Configuración raíz del proyecto
├── dependencies.lock        # Lock de dependencias
└── programa                 # Notas del proyecto
```

---

## Configuración

Antes de compilar, configura las credenciales de red y la URL del servidor con `menuconfig`:

```bash
idf.py menuconfig
```

Dentro del menú, ve a **"Coms Menu"** y configura:

| Parámetro | Descripción | Default |
|---|---|---|
| `WIFI_SSID` | Nombre de tu red WiFi 2.4GHz | — |
| `WIFI_PASS` | Contraseña de tu red WiFi | — |
| `SERVER_BASE_URL` | URL base del servidor | `testing.hansraddatz.com` |
| `WIFI_MAXIMUM_RETRY` | Máximos reintentos de conexión | `5` |
| `USE_HTTPS` | Usar HTTPS en las peticiones | `y` |

> No es necesario modificar el código fuente para cambiar credenciales.

---

## Compilar y flashear

```bash
# 1. Configurar el puerto serie (ajusta según tu sistema)
idf.py set-target esp32

# 2. Configurar credenciales
idf.py menuconfig

# 3. Compilar
idf.py build

# 4. Flashear al ESP32 (ajusta el puerto COM)
idf.py -p COM3 flash

# 5. Ver logs en tiempo real
idf.py -p COM3 monitor
```

En Linux/macOS el puerto es `/dev/ttyUSB0` o `/dev/ttyACM0` en lugar de `COM3`.

---

## Flujo de ejecución

```
app_main()
    └── custom_wifi_init()
            ├── Inicializa NVS (almacenamiento no volátil)
            ├── Configura WiFi en modo estación
            ├── Conecta a la red (con reintentos automáticos)
            └── Al conectar → registra IP y habilita HTTP client
```

---

## Componente WiFi (`coms/wifi.c`)

Maneja la conexión usando **FreeRTOS Event Groups** para sincronización asíncrona:

- `WIFI_CONNECTED_BIT` — se activa al obtener IP
- `WIFI_FAIL_BIT` — se activa al agotar los reintentos

El componente bloquea `app_main` hasta conectar o fallar, lo que simplifica la lógica de inicio.

---

## Módulo RFID RC522

El componente `esp-idf-rc522-master` permite leer tarjetas MIFARE. La inicialización se incluye en `main.c` mediante:

```c
#include "rc522.h"
```

Conectar el RC522 al ESP32 vía SPI:

| RC522 | ESP32 |
|---|---|
| SDA (SS) | GPIO 5 |
| SCK | GPIO 18 |
| MOSI | GPIO 23 |
| MISO | GPIO 19 |
| RST | GPIO 27 |
| 3.3V | 3.3V |
| GND | GND |

---

## En desarrollo

- `coms/http-req.c` — Cliente HTTP para enviar datos al servidor (en progreso)
- Integración de lectura RFID con envío HTTP

---

## Autor

**Tyler Rojas** — [GitHub](https://github.com/Tyler0125)
