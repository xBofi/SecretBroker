"""Ready-made settings for the API keys of well-known providers, so a credential prepared by the AI
(or imported from a .env file) works the first time: API URL, how the key is sent and its usual
environment variable. Only facts from each provider's own documentation."""

# id: (name, base_url, auth_style, env_var, how to use it when the key can't be added automatically)
PRESETS = {
    "openai": ("OpenAI", "https://api.openai.com/v1", "bearer", "OPENAI_API_KEY", ""),
    "anthropic": ("Anthropic", "https://api.anthropic.com", "x_api_key", "ANTHROPIC_API_KEY",
                  "Añade también la cabecera anthropic-version: 2023-06-01."),
    "openrouter": ("OpenRouter", "https://openrouter.ai/api/v1", "bearer", "OPENROUTER_API_KEY", ""),
    "github": ("GitHub", "https://api.github.com", "bearer", "GITHUB_TOKEN", ""),
    "gitlab": ("GitLab", "https://gitlab.com/api/v4", "bearer", "GITLAB_TOKEN", ""),
    "stripe": ("Stripe", "https://api.stripe.com", "bearer", "STRIPE_SECRET_KEY", ""),
    "groq": ("Groq", "https://api.groq.com/openai/v1", "bearer", "GROQ_API_KEY", ""),
    "huggingface": ("Hugging Face", "https://huggingface.co", "bearer", "HF_TOKEN", ""),
    "mistral": ("Mistral", "https://api.mistral.ai/v1", "bearer", "MISTRAL_API_KEY", ""),
    "cloudflare": ("Cloudflare", "https://api.cloudflare.com/client/v4", "bearer", "CLOUDFLARE_API_TOKEN", ""),
    "assemblyai": ("AssemblyAI", "https://api.assemblyai.com", "none", "ASSEMBLYAI_API_KEY",
                   "Envía la clave en la cabecera Authorization: {{value}} (sin Bearer)."),
    "elevenlabs": ("ElevenLabs", "https://api.elevenlabs.io", "none", "ELEVENLABS_API_KEY",
                   "Envía la clave en la cabecera xi-api-key: {{value}}."),
    "deepgram": ("Deepgram", "https://api.deepgram.com", "none", "DEEPGRAM_API_KEY",
                 "Envía la clave en la cabecera Authorization: Token {{value}}."),
}

# Other names projects give to the same keys.
ENV_ALIASES = {"GH_TOKEN": "github", "GITHUB_PAT": "github", "CF_API_TOKEN": "cloudflare",
               "HUGGINGFACE_API_KEY": "huggingface", "HUGGING_FACE_HUB_TOKEN": "huggingface", "XI_API_KEY": "elevenlabs",
               "STRIPE_API_KEY": "stripe", "CLAUDE_API_KEY": "anthropic"}


def get(preset_id):
    return PRESETS.get(str(preset_id or "").lower())


def for_env_var(name):
    """The provider an environment variable name points to, if it is unambiguous."""
    name = name.upper()
    if name in ENV_ALIASES:
        return ENV_ALIASES[name]
    return next((pid for pid, p in PRESETS.items() if p[3] == name), None)


def apply(preset_id, fields, description):
    """(fields, description) with the preset's values filled in where the caller left them empty."""
    preset = get(preset_id)
    if not preset:
        raise KeyError(preset_id)
    _, base_url, auth_style, env_var, usage = preset
    fields = {"base_url": base_url, "auth_style": auth_style, "env_var": env_var, **{k: v for k, v in fields.items() if v}}
    if usage and usage not in description:
        description = (description + "\n\n" if description else "") + usage
    return fields, description
