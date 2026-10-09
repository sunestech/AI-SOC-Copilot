from pathlib import Path
import re

path = Path("src/dashboard/06_streamlit_soc_dashboard.py")

if not path.exists():
    raise FileNotFoundError(f"Dashboard not found: {path}")

text = path.read_text(encoding="utf-8")

old_block = '''if st.sidebar.button("Refresh data"):
    st.cache_data.clear()
    st.cache_resource.clear()
    st.rerun()
'''

new_block = '''# ------------------------------------------------------------
# Refresh controls
# ------------------------------------------------------------
if "refresh_count" not in st.session_state:
    st.session_state["refresh_count"] = 0

if "last_refresh" not in st.session_state:
    st.session_state["last_refresh"] = "Not refreshed yet"

if "refresh_notice" not in st.session_state:
    st.session_state["refresh_notice"] = ""

if st.sidebar.button("🔄 Refresh dashboard data", use_container_width=True):
    st.session_state["refresh_count"] += 1
    st.session_state["last_refresh"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state["refresh_notice"] = "Dashboard data refreshed from disk."
    st.cache_data.clear()
    st.rerun()

if st.sidebar.button("♻️ Reload AI/retrieval resources", use_container_width=True):
    st.session_state["refresh_count"] += 1
    st.session_state["last_refresh"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state["refresh_notice"] = "Dashboard data and AI/retrieval resources reloaded."
    st.cache_data.clear()
    st.cache_resource.clear()
    st.rerun()

st.sidebar.caption(f"Last refresh: {st.session_state['last_refresh']}")
st.sidebar.caption(f"Refresh count: {st.session_state['refresh_count']}")
'''

if old_block in text:
    text = text.replace(old_block, new_block)
else:
    # Fallback insertion before sidebar divider if the old block was already changed.
    marker = "st.sidebar.divider()"
    if marker not in text:
        raise RuntimeError("Could not find sidebar insertion point.")

    if "Refresh controls" not in text:
        text = text.replace(marker, new_block + "\n" + marker)

# Add a visible success message near the top after the hero block.
notice_block = '''if st.session_state.get("refresh_notice"):
    st.success(st.session_state["refresh_notice"])
    st.session_state["refresh_notice"] = ""
'''

if "st.session_state.get(\"refresh_notice\")" not in text:
    marker = "# ============================================================\n# Pages"
    if marker not in text:
        raise RuntimeError("Could not find Pages marker.")

    text = text.replace(marker, notice_block + "\n" + marker)

path.write_text(text, encoding="utf-8")

print("Refresh controls patched successfully.")
print("- Added visible last-refresh timestamp")
print("- Added refresh counter")
print("- Added dashboard-only refresh")
print("- Added full AI/retrieval reload")
print("- Added success message after refresh")
print(path)
