from __future__ import annotations

from typing import Any

import streamlit as st

from security_research_agent import ApiKeys, SecurityResearchAgent
from security_research_agent.agent import MAX_QUERY_CHARACTERS
from security_research_agent.config import Settings, environment_key

st.set_page_config(
    page_title="Domain Research Agent",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)


APP_CSS = """
<style>
    :root {
        --ink: #14201d;
        --muted: #60706b;
        --paper: #f6f3eb;
        --line: #d8d4ca;
        --signal: #0f766e;
    }
    .stApp { background: var(--paper); color: var(--ink); }
    [data-testid="stSidebar"] { background: #ece9df; border-right: 1px solid var(--line); }
    [data-testid="stSidebar"] hr { border-color: var(--line); }
    .block-container { max-width: 1040px; padding-top: 2.2rem; }
    h1, h2, h3 { letter-spacing: -0.025em; }
    .eyebrow {
        color: var(--signal); font-size: .76rem; font-weight: 750;
        letter-spacing: .12em; text-transform: uppercase; margin-bottom: .45rem;
    }
    .project-title { font-size: clamp(2rem, 5vw, 3.6rem); line-height: 1.02; margin: 0; }
    .lede { color: var(--muted); font-size: 1.05rem; max-width: 720px; margin: .8rem 0 1.4rem; }
    .instruction-card {
        background: rgba(255,255,255,.58); border: 1px solid var(--line);
        border-radius: 14px; padding: 1rem 1.15rem; margin: .8rem 0 1.2rem;
    }
    .instruction-card strong { color: var(--ink); }
    .tool-row { display: flex; flex-wrap: wrap; gap: .45rem; margin-top: .65rem; }
    .tool-chip {
        border: 1px solid #b9c8c3; background: #eef6f3; color: #31524a;
        padding: .23rem .55rem; border-radius: 999px; font-size: .78rem;
    }
    .connection-row {
        display:flex; align-items:center; justify-content:space-between;
        gap:.7rem; padding:.42rem 0; font-size:.88rem;
    }
    .status-ok, .status-off {
        border-radius:999px; padding:.13rem .48rem; font-size:.7rem; font-weight:700;
        text-transform:uppercase; letter-spacing:.04em;
    }
    .status-ok { color:#0f5e51; background:#cfeee6; }
    .status-off { color:#656b69; background:#dddcd7; }
    [data-testid="stChatMessage"] {
        background: rgba(255,255,255,.55); border: 1px solid var(--line);
        border-radius: 14px; padding: .3rem .8rem; margin-bottom: .7rem;
    }
    [data-testid="stChatInput"] { border-color: #b8c1bd; }
    .priority {
        display:inline-flex; align-items:center; gap:.4rem; border-radius:999px;
        padding:.24rem .58rem; margin-bottom:.55rem; font-size:.72rem;
        font-weight:800; letter-spacing:.06em; text-transform:uppercase;
        background:#e5e7e6; color:#45504c;
    }
    .priority-high { background:#f6d7d2; color:#9d2b1e; }
    .priority-medium { background:#f7e6bf; color:#8a5608; }
    .mode-note { color:var(--muted); font-size:.72rem; margin-top:.35rem; }
    div.stButton > button { border-radius: 10px; border-color: #c5c2b9; }
</style>
"""
st.markdown(APP_CSS, unsafe_allow_html=True)


WELCOME_MESSAGE = """I can check one **public domain** at a time using a read-only
reputation source, then show the evidence behind the result.

Turn on **Offline demo mode** and try **`Check example.com`**, or connect VirusTotal for
a live domain lookup."""


def initialize_state() -> None:
    if "messages" not in st.session_state:
        st.session_state.messages = [{"role": "assistant", "content": WELCOME_MESSAGE}]
    if "session_api_keys" not in st.session_state:
        st.session_state.session_api_keys = {}
    if "selected_model" not in st.session_state:
        st.session_state.selected_model = Settings().openai_model
    if "demo_mode" not in st.session_state:
        st.session_state.demo_mode = Settings().demo_mode


def resolved_keys() -> ApiKeys:
    session_keys = st.session_state.session_api_keys
    return ApiKeys(
        openai=session_keys.get("openai") or environment_key("OPENAI_API_KEY"),
        virustotal=session_keys.get("virustotal") or environment_key("VIRUSTOTAL_API_KEY"),
    )


def connection_row(label: str, state: str, css_class: str) -> None:
    st.markdown(
        f'<div class="connection-row"><span>{label}</span>'
        f'<span class="{css_class}">{state}</span></div>',
        unsafe_allow_html=True,
    )


def apply_session_keys() -> None:
    fields = {
        "openai": "openai_key_field",
        "virustotal": "virustotal_key_field",
    }
    for name, field_name in fields.items():
        value = st.session_state.get(field_name, "").strip()
        if value:
            st.session_state.session_api_keys[name] = value
        st.session_state[field_name] = ""


def clear_session_keys() -> None:
    st.session_state.session_api_keys = {}
    for field_name in ("openai_key_field", "virustotal_key_field"):
        st.session_state[field_name] = ""


def queue_prompt(prompt: str) -> None:
    st.session_state.pending_prompt = prompt


def render_evidence(message: dict[str, Any]) -> None:
    evidence = message.get("evidence") or []
    if evidence:
        with st.expander(f"Evidence and tool trace · {len(evidence)} source(s)"):
            tools_used = message.get("tools_used") or []
            if tools_used:
                st.caption("Tools used: " + " → ".join(tools_used))
            st.json(evidence, expanded=False)
    if message.get("mode"):
        st.markdown(
            f'<div class="mode-note">Response mode: {message["mode"]}</div>',
            unsafe_allow_html=True,
        )


initialize_state()


with st.sidebar:
    st.markdown("## Connections")
    st.caption(
        "Keys stay in this local app session and are not written to disk. "
        "You can also use a local `.env` file."
    )

    keys = resolved_keys()
    connection_row(
        "OpenAI",
        "connected" if keys.openai else "optional",
        "status-ok" if keys.openai else "status-off",
    )
    connection_row(
        "VirusTotal",
        "connected" if keys.virustotal else "optional",
        "status-ok" if keys.virustotal else "status-off",
    )
    st.divider()
    with st.expander("Add API keys", expanded=not bool(keys.openai)):
        st.text_input(
            "OpenAI API key",
            key="openai_key_field",
            type="password",
            placeholder="sk-…",
            help="Optional. Without it, the app uses its deterministic local report.",
        )
        st.text_input(
            "VirusTotal API key",
            key="virustotal_key_field",
            type="password",
            placeholder="Required for live domain lookups",
        )
        st.button(
            "Use keys for this session",
            type="primary",
            use_container_width=True,
            on_click=apply_session_keys,
        )

        st.button(
            "Clear session keys",
            use_container_width=True,
            on_click=clear_session_keys,
        )
        st.caption(
            "OpenAI receives the normalized domain and evidence. VirusTotal receives the "
            "domain. Do not enter credentials or internal targets."
        )

    st.text_input(
        "OpenAI model",
        key="selected_model",
        help="The model name is configurable so the sample does not depend on one model release.",
    )
    st.toggle(
        "Offline demo mode",
        key="demo_mode",
        help="Uses clearly labeled fixture data and makes no network or OpenAI requests.",
    )

    st.divider()
    if st.button("Clear chat", use_container_width=True):
        st.session_state.messages = [{"role": "assistant", "content": WELCOME_MESSAGE}]
        st.rerun()
    st.caption("Read-only by design · no scanning · no file uploads")


st.markdown(
    '<div class="eyebrow">Local domain intelligence workbench</div>',
    unsafe_allow_html=True,
)
st.markdown('<h1 class="project-title">Domain Research Agent</h1>', unsafe_allow_html=True)
st.markdown(
    '<p class="lede">A focused, evidence-first agent for checking public domain reputation '
    "without scanning or submitting content.</p>",
    unsafe_allow_html=True,
)
st.markdown(
    """
    <div class="instruction-card">
      <strong>What you can do</strong><br>
      Enter one bare public domain, such as <code>example.com</code>. The app retrieves
      passive DNS, registration, and certificate evidence, plus an existing VirusTotal
      report when that connection is available. URLs, IP addresses, CVEs, hashes,
      email addresses, and internal domains are intentionally rejected.
      <div class="tool-row">
        <span class="tool-chip">Cloudflare DNS</span>
        <span class="tool-chip">RDAP</span>
        <span class="tool-chip">Certificate Transparency</span>
        <span class="tool-chip">VirusTotal (optional)</span>
        <span class="tool-chip">OpenAI (optional)</span>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)


quick_columns = st.columns(2)
with quick_columns[0]:
    st.button(
        "Check example.com",
        use_container_width=True,
        on_click=queue_prompt,
        args=("Check example.com",),
    )
with quick_columns[1]:
    st.button(
        "Explain the safety limits",
        use_container_width=True,
        on_click=queue_prompt,
        args=("What can this demo do, and what actions are intentionally blocked?",),
    )

quick_prompt = st.session_state.pop("pending_prompt", None)


for stored_message in st.session_state.messages:
    with st.chat_message(stored_message["role"]):
        priority = stored_message.get("priority")
        if priority and priority != "unknown":
            st.markdown(
                f'<div class="priority priority-{priority}">{priority} priority</div>',
                unsafe_allow_html=True,
            )
        st.markdown(stored_message["content"])
        render_evidence(stored_message)


typed_prompt = st.chat_input(
    "Enter one public domain, such as example.com",
    max_chars=MAX_QUERY_CHARACTERS,
)
prompt = typed_prompt or quick_prompt
if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    base_settings = Settings()
    settings = Settings(
        openai_model=st.session_state.selected_model.strip() or base_settings.openai_model,
        request_timeout_seconds=base_settings.request_timeout_seconds,
        max_response_characters=base_settings.max_response_characters,
        demo_mode=st.session_state.demo_mode,
    )
    agent = SecurityResearchAgent(settings)
    with st.chat_message("assistant"):
        with st.spinner("Checking domain evidence…"):
            outcome = agent.run(
                prompt,
                api_keys=resolved_keys(),
                demo_mode=st.session_state.demo_mode,
            )
        if outcome.priority.value != "unknown":
            st.markdown(
                f'<div class="priority priority-{outcome.priority.value}">'
                f"{outcome.priority.value} priority</div>",
                unsafe_allow_html=True,
            )
        st.markdown(outcome.message)
        stored_outcome = {
            "role": "assistant",
            "content": outcome.message,
            "priority": outcome.priority.value,
            "priority_reasons": outcome.priority_reasons,
            "evidence": [item.model_dump(mode="json") for item in outcome.evidence],
            "tools_used": outcome.tools_used,
            "mode": outcome.mode,
        }
        render_evidence(stored_outcome)
    st.session_state.messages.append(stored_outcome)
