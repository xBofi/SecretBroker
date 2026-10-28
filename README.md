# SecretBroker

Bóveda de credenciales para Windows que permite a un agente de IA (Claude Code u otro cliente MCP) **usar** tus API keys, contraseñas y accesos **sin poder leerlos nunca**.

```
 Tú (app SecretBroker)                 Servicio SecretBroker               Internet / servidores
 ─ guardas claves con plantillas  ──▶  (cuenta de Windows aparte)    ──▶  HTTPS · SSH · CLIs
 ─ apruebas con Windows Hello          ─ bóveda cifrada                    con la clave inyectada
                                       ─ verifica tu firma Hello
 Claude ── MCP: «usa 'github'» ─────▶  ─ ejecuta y censura la salida ◀── respuesta sin secretos
```

## Instalación

Ejecuta `SecretBroker-Setup-<versión>.exe` y acepta el aviso de administrador. No hace falta internet ni escribir nada. El instalador:
1. Instala la app y su propio Python en `C:\Program Files\SecretBroker`, donde solo pueden escribir los administradores.
2. Crea la cuenta oculta `SecretBroker`, que no puede iniciar sesión ni usarse por red.
3. Crea `C:\ProgramData\SecretBroker\data`, que **solo esa cuenta** puede leer.
4. Importa una bóveda anterior si la hay, registra el servicio para que arranque con Windows y lo inicia.
5. Crea los accesos directos y conecta Claude Code y Claude Desktop si están instalados (también se puede hacer luego desde Ajustes → IA).

Para actualizar, ejecuta el instalador nuevo encima: se conservan la bóveda, la cuenta y el desbloqueo con Windows. Para desinstalar, usa «Aplicaciones instaladas» de Windows. El desinstalador quita el servicio y su cuenta, desconecta Claude Code y Claude Desktop y borra tus preferencias. Después pregunta si quieres borrar también la bóveda. Por defecto la respuesta es «No», y entonces se conserva en `C:\ProgramData\SecretBroker\data`.

Sin instalar, la app funciona en **modo de desarrollo** (`.venv\Scripts\secretbroker.exe`): es la misma app, pero sin aislamiento.

### Generar el instalador

```powershell
winget install JRSoftware.InnoSetup      # una vez
powershell -ExecutionPolicy Bypass -File .\tools\build_installer.ps1
```

El resultado es `dist\SecretBroker-Setup-<versión>.exe`, de unos 26 MB, con Python y todas las dependencias incluidos. El `.exe` no está firmado, así que Windows SmartScreen mostrará «Windows protegió su PC» (Más información → Ejecutar de todas formas). Para distribuirlo sin ese aviso hay que firmarlo con un certificado de firma de código.

## Uso

- **Plantillas**: web o servicio, API key, servidor SSH, base de datos, AWS u otro secreto. Cada una muestra solo los campos que necesita.
- **Notas para la IA**: texto que la IA sí lee, para explicarle qué es cada credencial y cómo usarla.
- **Permisos de la IA**: se rellenan solos a partir de la plantilla (por ejemplo, el dominio sale de la URL). Incluyen las webs permitidas, la cabecera de autenticación, los programas locales permitidos y sus variables de entorno, y cuándo pedir aprobación.
- **Windows Hello**: con tu PIN, huella o cara desbloqueas la bóveda, apruebas usos, ves o copias contraseñas y guardas cambios. En PCs sin Hello se usa la contraseña de Windows o la maestra.
- **Recuperación**: si olvidas la contraseña maestra, entra con Windows Hello o con la contraseña de Windows y crea una nueva. Esto solo funciona en este PC.
- **Copiar**: el portapapeles se borra a los 30 s y la contraseña no pasa al historial del portapapeles.

### Herramientas MCP

| Herramienta | Qué hace |
|---|---|
| `list_secrets` | Catálogo con el contexto de cada credencial, sin valores |
| `http_request` | Petición HTTPS a un dominio permitido; admite autenticación automática o marcadores `{{value}}`, `{{username}}` y `{{password}}` |
| `ssh_exec` · `ssh_upload` · `ssh_download` | Comandos (también con sudo) y transferencia de archivos por SFTP |
| `run_command` | Ejecuta un programa permitido (`gh`, `psql`, `aws`…) con la credencial en variables de entorno |

Si la bóveda está bloqueada o hace falta una aprobación, el MCP abre la app y espera.

## Modelo de seguridad

| Amenaza | Protección |
|---|---|
| La IA lee un secreto | Ninguna operación de la IA devuelve valores. Las salidas se censuran: texto literal, base64, codificación URL, JSON y cadenas de conexión. |
| Lectura de la memoria del servicio o de sus archivos | El servicio corre con otra cuenta de Windows; sin elevación de administrador, nadie puede leerlo. |
| Modificar el código para que filtre claves | El código está en Program Files y se ejecuta con `python -I`, que ignora variables de entorno y módulos del usuario. |
| Falsificar una aprobación o un desbloqueo | El servicio exige una **firma de Windows Hello** (clave en el TPM) sobre un desafío de un solo uso, ligado a esa operación concreta. |
| Registrar una clave Hello falsa | Para registrar Hello hace falta la contraseña maestra o la de Windows. |
| Suplantar al servicio | Cada respuesta va firmada (Ed25519) con una clave que solo tiene el servicio real. |
| Enviar la clave a otro sitio | Lista blanca de dominios por credencial, solo HTTPS, sin seguir redirecciones; el host SSH sale de la bóveda. |
| Robo del disco | scrypt (128 MiB) + AES-256-GCM; la clave del equipo además va protegida con DPAPI. |
| Leer el historial de actividad | Cada entrada se cifra con una clave pública (X25519 + AES-256-GCM) derivada de la bóveda: se puede escribir con la bóveda bloqueada, pero solo se lee desbloqueada. |
| Fuerza bruta de contraseñas | Retardo creciente tras cada fallo. |

**Límites conocidos.** Todo lo que pasa por tu escritorio es visible para los programas de tu sesión: un programa malicioso podría ver el portapapeles cuando copias una clave para pegarla en la app, capturar teclas o superponer ventanas falsas. Esto le ocurre igual a cualquier gestor de contraseñas. Aprueba solo solicitudes que esperes, y **nunca ejecutes Claude Code como administrador**. Los programas permitidos en `run_command` reciben la credencial, así que permite solo los necesarios.

## Desarrollo

```powershell
python -m venv .venv; .venv\Scripts\python.exe -m pip install .
.venv\Scripts\python.exe tests\test_e2e.py   # servicio, pruebas de identidad, aprobaciones, acciones, MCP
.venv\Scripts\python.exe tests\test_ssh.py   # SSH contra un servidor de prueba local
python tools\make_icon.py secretbroker\assets\icon.ico
```

La interfaz sigue el sistema de diseño documentado al principio de `secretbroker/web/styles.css`: un único color de acento por paleta (Salvia, Cobalto, Terracota, Grafito), los colores de categoría solo en los iconos y la jerarquía marcada con el peso del texto, no con cajas.

```text
Atajos: Ctrl+F buscar · Ctrl+N nueva credencial · Ctrl+L bloquear · Esc cerrar
```
