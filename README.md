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

Descarga `SecretBroker-Setup-<versión>.exe` de la [página de versiones](https://github.com/xBofi/SecretBroker/releases/latest), ejecútalo y acepta el aviso de administrador. No hace falta internet ni escribir nada. El instalador:
1. Instala la app y su propio Python en `C:\Program Files\SecretBroker`, donde solo pueden escribir los administradores.
2. Crea la cuenta oculta `SecretBroker`, que no puede iniciar sesión ni usarse por red.
3. Crea `C:\ProgramData\SecretBroker\data`, que **solo esa cuenta** puede leer.
4. Importa una bóveda anterior si la hay, registra el servicio para que arranque con Windows y lo inicia.
5. Crea los accesos directos y conecta Claude Code y Claude Desktop si están instalados (también se puede hacer luego desde Ajustes → IA).

**Actualizaciones.** La app comprueba cada pocas horas si hay una versión nueva en GitHub y lo indica en la barra lateral. Al pulsar «Actualizar», el servicio descarga el instalador y comprueba su firma, Windows pide permiso de administrador y la app se reabre actualizada. Se conservan la bóveda, la cuenta y el desbloqueo con Windows. Solo se instalan versiones firmadas con la clave de publicación (Ed25519; la clave pública va en `secretbroker/update.py`, dentro de Program Files). También se puede ejecutar el instalador nuevo encima a mano. Para desinstalar, usa «Aplicaciones instaladas» de Windows. El desinstalador quita el servicio y su cuenta, desconecta Claude Code y Claude Desktop y borra tus preferencias. Después pregunta si quieres borrar también la bóveda. Por defecto la respuesta es «No», y entonces se conserva en `C:\ProgramData\SecretBroker\data`.

Sin instalar, la app funciona en **modo de desarrollo** (`.venv\Scripts\secretbroker.exe`): es la misma app, pero sin aislamiento.

### Publicar una versión

Sube la versión en `pyproject.toml`, `secretbroker/__init__.py` e `installer/SecretBroker.iss`, y empuja una etiqueta `v<versión>`. GitHub Actions (`.github/workflows/release.yml`) pasa las pruebas, compila el instalador, lo firma con el secret `UPDATE_SIGNING_KEY` y lo publica en Releases. Las apps instaladas lo verán solas. La clave de firma se creó con `tools/new_signing_key.py`, que solo imprime la clave pública y la privada ya cifrada para GitHub.

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
- **Aprobaciones**: la contraseña se escribe al desbloquear; después, aprobar lo que pide la IA es un clic. «Permitir hoy» deja a la IA usar esa credencial sin volver a preguntar durante 24 h (configurable: 8 h, 24 h o hasta bloquear), también tras el bloqueo automático. Bloquear a mano las olvida todas. Las credenciales con aprobación «Nunca» no preguntan nunca.
- **Windows Hello**: con tu PIN, huella o cara desbloqueas la bóveda, apruebas usos, ves o copias contraseñas y guardas cambios. En PCs sin Hello se usa la contraseña de Windows o la maestra.
- **Recuperación**: si olvidas la contraseña maestra, entra con Windows Hello o con la contraseña de Windows y crea una nueva. Esto solo funciona en este PC.
- **Copiar**: el portapapeles se borra a los 30 s y la contraseña no pasa al historial del portapapeles.
- **Enlaces al proveedor**: las API keys de proveedores conocidos (OpenAI, Anthropic, GitHub, GitLab, Cloudflare, Stripe, OpenRouter, Mistral…) muestran enlaces directos a su página de claves, a la de crear una nueva y a la facturación. En Cloudflare se indica además el tipo de credencial (token de usuario o de cuenta, Global API Key, AI Gateway, R2, Access). Las de AI Gateway enlazan al panel de su cuenta y nombran su gateway.
- **Rotar**: en las API keys de proveedores que permiten crear claves por API (por ahora **Cloudflare** y **GitLab**), el botón «Rotar clave» pide una clave nueva al proveedor, la guarda y la vuelve a subir a los secrets de GitHub donde se subió con `push_github_secret`. La clave vieja deja de funcionar al momento. En los proveedores que no lo permiten (OpenAI sin Admin key, Anthropic, GitHub, AssemblyAI…) el botón aparece desactivado con el motivo.
- **Exposición**: cada credencial tiene un semáforo que dice si sigue estando solo en la bóveda.
  - *Copias en claro*: al desbloquear (como mucho cada 12 h) o a mano, la app busca tus claves en las conversaciones de Claude Code y Codex, los historiales de PowerShell y bash, la configuración de programas (`.claude.json`, Claude Desktop, `.npmrc`, `.aws`, `.ssh`…), las variables de entorno, las carpetas de proyectos (las de Claude Code y las que añadas) y su historial de git. Busca también las formas en JSON, URL y base64. Después de la primera vez solo lee lo que ha cambiado.
  - *¿Sigue funcionando?*: una vez al día prueba cada clave con una llamada de solo lectura a su proveedor (OpenAI, Anthropic, AssemblyAI, GitHub, Stripe, ElevenLabs, Cloudflare…) y los servidores SSH. Si una clave que funcionaba deja de hacerlo, avisa: lo normal es que el proveedor la haya revocado al encontrarla filtrada. Una clave solo se envía al proveedor de su URL o de un prefijo inequívoco (`sk-ant-`, `ghp_`…).
  - *Filtraciones*: las contraseñas se comprueban en Have I Been Pwned por k-anonimato (solo salen 5 caracteres de su hash SHA-1).
  - Además muestra la antigüedad del valor actual y cuántas veces se ha mostrado o copiado. Al cambiar el valor (rotarla), su historial empieza de cero.

### Herramientas MCP

| Herramienta | Qué hace |
|---|---|
| `list_secrets` | Catálogo con el contexto de cada credencial, sin valores |
| `http_request` | Petición HTTPS a un dominio permitido; admite autenticación automática o marcadores `{{value}}`, `{{username}}` y `{{password}}` |
| `ssh_exec` · `ssh_upload` · `ssh_download` | Comandos (también con sudo) y transferencia de archivos por SFTP |
| `run_command` | Ejecuta un programa permitido (`gh`, `psql`, `aws`…) con la credencial en variables de entorno |
| `create_credential` | Prepara una credencial nueva con todo (plantilla, notas, URL, permisos, variables) menos la clave. El usuario solo la pega en la app; hasta entonces no se puede usar |
| `update_credential` | Cambia nombre, notas, campos o permisos. El nombre y las notas cambian al momento; lo que decide adónde puede ir una clave ya guardada espera la aprobación del usuario. Nunca toca valores secretos ni el modo de aprobación |
| `push_github_secret` | Guarda una credencial como secret de GitHub Actions (del repositorio o de un entorno), cifrada con la clave del repositorio y sin que la IA vea el valor |

### Tus apps en local: `sb run`

Para que tus programas usen las credenciales sin guardar un `.env` con valores en el proyecto:

1. Crea un `.secretbroker` en la raíz del proyecto. Solo dice de qué credencial sale cada variable, así que se puede subir a git:
   ```
   OPENAI_API_KEY = openai                  # la plantilla de esa variable en la credencial, o {{value}}
   DATABASE_URL   = tienda-db:connection_url # un dato concreto de la credencial
   aws-prod                                 # todas las variables de entorno de la credencial
   ```
2. Arranca la app con `sb run -- npm run dev` (o `python app.py`, `dotnet run`…). Las variables llegan de la bóveda al proceso directamente, sin pasar por ningún archivo.

Tu código solo lee variables de entorno, así que en producción funciona igual con las que ponga la plataforma: por ejemplo, `env: OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}` en GitHub Actions. La IA puede subir esos secrets con `push_github_secret`, y tras rotar una clave basta con volver a subirla.

- Solo se entregan credenciales que tengan variables de entorno en sus *Permisos de la IA*. Es tu forma de decir que esa credencial se puede usar en programas locales.
- La aprobación sigue la de cada credencial, igual que el resto de usos, y cada entrega queda en el historial con el comando y la carpeta.
- Si la salida no va a una terminal (por ejemplo, cuando la app la arranca una IA), `sb` censura las claves línea a línea.
- **Límite:** el programa recibe la clave en claro. Esto evita que la IA la vea por accidente (un `cat .env`, un log), pero no protege de código escrito a propósito para filtrarla.

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
| Usar el análisis de exposición para adivinar contraseñas («¿está este texto en la bóveda?») | El servicio solo busca dentro de una sesión de análisis, que se entrega al desbloquear o tras verificar la identidad y caduca al bloquear. Sin ella, el informe dice qué credenciales están expuestas, pero no en qué archivos. |

**Límites conocidos.** Todo lo que pasa por tu escritorio es visible para los programas de tu sesión: un programa malicioso podría ver el portapapeles cuando copias una clave para pegarla en la app, capturar teclas o superponer ventanas falsas. Esto le ocurre igual a cualquier gestor de contraseñas. Aprueba solo solicitudes que esperes, y **nunca ejecutes Claude Code como administrador**. Los programas permitidos en `run_command` reciben la credencial, así que permite solo los necesarios.

## Desarrollo

```powershell
python -m venv .venv; .venv\Scripts\python.exe -m pip install .
.venv\Scripts\python.exe tests\test_e2e.py   # servicio, pruebas de identidad, aprobaciones, acciones, MCP
.venv\Scripts\python.exe tests\test_ssh.py   # SSH contra un servidor de prueba local
.venv\Scripts\python.exe tests\test_exposure.py   # análisis de exposición contra un perfil de usuario falso (necesita git)
python tools\make_icon.py secretbroker\assets\icon.ico
.\tools\update_installed.ps1         # pasa el código a la versión instalada y reinicia el servicio (pide UAC)
.\tools\update_installed.ps1 -Full   # igual, pero con el instalador completo (si cambian dependencias o installer\)
```

La interfaz sigue el sistema de diseño documentado al principio de `secretbroker/web/styles.css`: un único color de acento por paleta (Salvia, Cobalto, Terracota, Grafito), los colores de categoría solo en los iconos y la jerarquía marcada con el peso del texto, no con cajas.

```text
Atajos: Ctrl+F buscar · Ctrl+N nueva credencial · Ctrl+L bloquear · Esc cerrar
```
