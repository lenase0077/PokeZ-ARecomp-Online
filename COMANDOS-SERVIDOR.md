# Guía de Comandos y Eventos del Servidor (Lumiose Private Server)

Esta guía resume todos los comandos disponibles para administrar el servidor privado, activar o desactivar eventos en vivo, repartir recompensas y usar el chat de Party.

---

## 1. Dónde y quién puede usarlos

Los comandos funcionan desde dos lugares:

1. **Chat dentro del juego**: escribiendo el comando con barra `/` (por ejemplo, `/events` o `/event shiny on`).
2. **Consola interactiva del servidor**: escribiendo el comando en la ventana/terminal donde corre el servidor **sin barra inicial** (por ejemplo, `events` o `event shiny on`).

### Permisos
- **Comandos públicos** (cualquier jugador conectado):
  - `/help` (o `/ayuda`, `/?`)
  - `/events` (o `/eventos`)
  - `/autoevent` (o `/autoevent status`)
  - `/p <mensaje>` (solo dentro de una Party)
- **Comandos de administrador**: requieren una de estas condiciones:
  - Estar ejecutando el comando desde la **consola del servidor**.
  - Tener `pid == 1` (host).
  - Conectarse desde loopback (`127.0.0.1`, `localhost` o `::1`).
  - Tener el `trainer_id` listado en `coop.admins` dentro de `lumiose/private-room-state.json`.

---

## 2. Comandos generales y chat

| Comando | Quién puede usarlo | Qué hace |
|---|---|---|
| `/help` (`/ayuda`, `/?`) | Todos | Muestra la lista resumida de comandos en el chat. |
| `/events` (`/eventos`) | Todos | Muestra el estado actual (`ON` / `OFF`) de todos los eventos del servidor. |
| `/p <mensaje>` | Miembros de una Party | Envía un mensaje privado solo a los integrantes actuales de tu Party. |
| `/say <mensaje>` | Admin / Consola | Envía un aviso global `[SERVER]` a todos los jugadores conectados. |

---

## 3. Eventos del servidor

### Ver y cambiar eventos
- `/events` (o `/eventos`): lista todos los eventos y si están activos o desactivados.
- `/event <nombre> <on|off>` (o `/evento <nombre> <on|off>`): activa o desactiva un evento en tiempo real y avisa a los jugadores conectados.
  - Valores aceptados para el estado: `on`, `off`, `1`, `0`, `si`, `no`, `true`, `false`.
  - También acepta el orden inverso (`/event on shiny`).

### Lista de eventos y alias

| Evento | Estado por defecto | Alias aceptados | Qué habilita o cambia |
|---|---|---|---|
| `raids` | `ON` (`True`) | `raid`, `raids` | Habilita o bloquea las Raids cooperativas y actualiza en vivo el acceso de Raids. |
| `nursery` | `ON` (`True`) | `nursery`, `huevos`, `daycare`, `egg`, `eggs` | Habilita o deshabilita la Guardería / Huevos. |
| `mystery_gift` | `ON` (`True`) | `gift`, `gifts`, `mystery`, `mystery_gift`, `regalo` | Habilita o deshabilita el canje de códigos de Mystery Gift. |
| `auto_events` | `ON` (`True`) | `auto`, `auto_events`, `auto_event`, `programados` | Activa el programador automático de Happy Hours rotativos y auto-raids mientras haya jugadores conectados. |
| `shiny_event` | `OFF` (`False`) | `shiny`, `shiny_event`, `charm` | Al activarlo, entrega un **Lumiose Shiny Charm** en la mochila de los jugadores conectados (y el Día 1 de racha diaria también entrega Charm mientras siga activo). |
| `instant_hatch` | `OFF` (`False`) | `hatch`, `instant_hatch`, `instanthatch` | Activa el modo de eclosión instantánea para la Guardería / Huevos. |
| `double_loot` | `OFF` (`False`) | `loot`, `double_loot`, `doble` | Activa recompensas dobles. |

**Ejemplos:**
```text
/event shiny on
/event hatch on
/event raids off
/evento huevos on
/event auto off
```

---

## 3.1 Eventos Automáticos (`/autoevent`)

Cuando `auto_events` está en `ON` y hay jugadores conectados, el servidor ejecuta automáticamente:
1. **Happy Hours rotativos** (por defecto: cada `45 min` dura `15 min`): rota entre `shiny_event` (Hora Shiny), `instant_hatch` (Guardería Turbo) y `double_loot` (Lluvia de Recompensas).
2. **Auto-Raids** (por defecto: cada `30 min` si `raids` está en `ON` y no hay otro Boss activo): abre un Raid Boss en el lobby y avisa en el chat.

| Comando | Quién puede usarlo | Qué hace |
|---|---|---|
| `/autoevent` o `/autoevent status` | Todos | Muestra el estado actual, cuánto falta para el próximo evento y el intervalo configurado. |
| `/autoevent now` (`next`, `ya`) | Admin / Consola | Dispara de inmediato el siguiente Happy Hour de la rotación. |
| `/autoevent stop` | Admin / Consola | Finaliza antes de tiempo el Happy Hour activo en ese momento. |
| `/autoevent interval <min>` | Admin / Consola | Cambia cada cuántos minutos se activa un Happy Hour (`1` a `1440`). |
| `/autoevent duration <min>` | Admin / Consola | Cambia cuántos minutos dura cada Happy Hour (`1` a `240`). |
| `/autoevent raid <min>` | Admin / Consola | Cambia cada cuántos minutos aparece un Auto-Raid (`0` desactiva solo los auto-raids; `1` a `1440`). |

---

## 4. Mystery Gift (códigos de regalo)

El servidor trae códigos precargados listos para canjear desde el menú de Mystery Gift del juego (mientras el evento `mystery_gift` esté en `ON`):

### Códigos incluidos por defecto

| Código | Recompensa |
|---|---|
| `SHINYZA` | Lumiose Shiny Charm x1 |
| `RAIDPARTY` | Raid Tickets x3 (límite máximo en posesión: 10) |
| `HOLAAMOR` | Lumiose Shiny Charm x2 + Raid Tickets x2 |

### Administrar códigos (Admin / Consola)

| Comando | Qué hace |
|---|---|
| `/gift` o `/gift list` | Lista los códigos de Mystery Gift activos actualmente. |
| `/gift add <CODIGO> <charm\|tickets\|bundle> [cantidad]` | Crea o actualiza un código de regalo. La cantidad va de `1` a `10` (si se omite, usa `1`; el código se pasa a mayúsculas, máximo 32 caracteres). |
| `/gift del <CODIGO>` | Elimina un código existente (también acepta `off` o `remove` en lugar de `del`). |

**Ejemplos:**
```text
/gift list
/gift add FINDE bundle 2
/gift add TICKETS10 tickets 5
/gift del FINDE
```

---

## 5. Recompensas directas y Raids (Admin / Consola)

| Comando | Qué hace |
|---|---|
| `/charm [cantidad]` | Entrega **Lumiose Shiny Charm** (de `1` a `10`, por defecto `1`) en la mochila de todos los jugadores conectados. |
| `/tickets [cantidad]` | Entrega **Raid Tickets** (de `1` a `10`, por defecto `1`, máximo total `10` por jugador) a todos los jugadores conectados. |
| `/raid` o `/raid spawn` | Genera un Raid Boss e inicia la batalla (requiere que el evento `raids` esté en `ON`). |
| `/raid clear` | Cierra la Raid activa en ese momento. |

---

## 6. Notas del servidor privado

- **Persistencia**: el estado de eventos, códigos de regalo, admins, amigos, racha diaria, mochila, tickets de Raid y slots de Guardería se guarda automáticamente en `lumiose/private-room-state.json`.
- **Mercado de Luminalia**: se encuentra desactivado a propósito en el servidor privado para evitar confusión en salas entre pocos jugadores.
