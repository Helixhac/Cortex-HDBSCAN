import sys
from pathlib import Path
 
# dashboard/ qovluğundan kənarda olan core/ qovluğunu görə bilmək üçün
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
 
import io
import json as _json
import pandas as pd
import streamlit as st
import plotly.express as px
from sklearn.decomposition import PCA
 
from db import load_alerts_df, init_db, get_conn, save_analyst_labels
from features import build_features
from report_builder import build_weekly_report_docx
 
st.set_page_config(page_title="Cortex XDR ML Monitor", page_icon="🛰️", layout="wide")
 
# ---- Yüngül SOC-üslublu görünüş: severity-lərə görə rəng kodlaması ----
st.markdown(
    """
    <style>
    .stMetric { background-color: rgba(120,120,120,0.07); border-radius: 8px; padding: 8px; }
    span.sev-high { color: #e6453c; font-weight: 700; }
    span.sev-medium { color: #e6a23c; font-weight: 700; }
    span.sev-low { color: #6c9ef8; font-weight: 700; }
    span.sev-informational, span.sev-unknown { color: #9aa0a6; font-weight: 700; }
    </style>
    """,
    unsafe_allow_html=True,
)
 
try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=60_000, key="auto_refresh")  # 60 saniyədə bir səhifəni yenilə
except ImportError:
    st.sidebar.info("Avtomatik yenilənmə üçün: pip install streamlit-autorefresh")
 
init_db()
st.title("🛰️ Cortex XDR — Alert İzləmə və Klasterləmə")
 
df = load_alerts_df()
 
if df.empty:
    st.warning(
        "DB-də hələ alert yoxdur. Əvvəlcə fon prosesini işə salın:\n\n"
        "`python scheduler.py`\n\nBu, Cortex XDR-dan alertləri çəkib bu DB-yə yazacaq."
    )
    st.stop()
 
df["creation_dt"] = pd.to_datetime(df["creation_time"], unit="ms", errors="coerce")
 
# ---- Üst KPI sətri ----
c1, c2, c3, c4 = st.columns(4)
c1.metric("Ümumi alert sayı", f"{len(df):,}")
import time as _time
now_ms_for_kpi = int(_time.time() * 1000)
last_24h = int((df["creation_time"] > now_ms_for_kpi - 24 * 60 * 60 * 1000).sum())
c2.metric("Son 24 saat", last_24h)
has_clusters = df["cluster_label"].notna().any()
n_clusters = int(df.loc[df["cluster_label"] >= 0, "cluster_label"].nunique()) if has_clusters else 0
c3.metric("Aşkarlanan cluster sayı", n_clusters if has_clusters else "—")
c4.metric("Son DB yazısı", df["fetched_at"].max() if "fetched_at" in df else "—")
 
st.divider()
 
# ---- Sidebar filtrləri ----
with st.sidebar:
    st.header("Filtrlər")
    sev_options = sorted(df["severity"].dropna().unique().tolist())
    sev_filter = st.multiselect("Severity", sev_options, default=sev_options)
    min_d, max_d = df["creation_dt"].min().date(), df["creation_dt"].max().date()
    date_range = st.date_input("Tarix aralığı", value=(min_d, max_d), min_value=min_d, max_value=max_d)
 
mask = df["severity"].isin(sev_filter) if sev_filter else pd.Series(True, index=df.index)
if isinstance(date_range, tuple) and len(date_range) == 2:
    mask &= (df["creation_dt"].dt.date >= date_range[0]) & (df["creation_dt"].dt.date <= date_range[1])
fdf = df[mask].copy()
 
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(
    ["📋 Alertlər", "🧩 Cluster analizi", "📈 Model statusu", "📝 Həftəlik Hesabat",
     "🚨 Anomaliyalar", "📊 Trendlər", "🏆 Risk Reytinqi"]
)
 
with tab1:
    st.caption(f"{len(fdf):,} alert göstərilir (filtrə uyğun)")
    show_cols = ["alert_id", "creation_dt", "severity", "alert_name", "category", "alert_source",
                 "host_name", "username", "description", "mitre_attack_technique",
                 "mitre_attack_tactic", "remote_ip", "remote_host", "country",
                 "rule_id", "incident_id", "resolution_status", "domain", "cluster_label",
                 "is_anomaly", "anomaly_reason"]
    show_cols = [c for c in show_cols if c in fdf.columns]
 
    with st.expander("➕ Əlavə field seç (Cortex-dan gələn istənilən field-i cədvələ əlavə et)"):
        all_keys = set()
        for raw in fdf["raw_json"].head(300):
            try:
                obj = _json.loads(raw)
                all_keys.update(obj.keys())
            except Exception:
                pass
        all_keys -= set(show_cols)
        extra_fields = st.multiselect("Mövcud field-lər (xam Cortex datasından)", sorted(all_keys), key="extra_fields_picker")
 
    if extra_fields:
        def _extract_extra(raw, fields):
            try:
                obj = _json.loads(raw)
            except Exception:
                obj = {}
            out = {}
            for f in fields:
                v = obj.get(f)
                if isinstance(v, list):
                    v = ", ".join(str(x) for x in v if x not in (None, "")) or None
                out[f] = v
            return out
 
        extra_df = pd.DataFrame([_extract_extra(r, extra_fields) for r in fdf["raw_json"]], index=fdf.index)
        display_df = pd.concat([fdf[show_cols], extra_df], axis=1)
    else:
        display_df = fdf[show_cols]
 
    st.dataframe(
        display_df.sort_values("creation_dt", ascending=False),
        use_container_width=True,
        height=520,
    )
 
    dl1, dl2 = st.columns(2)
    export_df = display_df.sort_values("creation_dt", ascending=False)
    dl1.download_button(
        "📥 CSV endir",
        data=export_df.to_csv(index=False).encode("utf-8-sig"),
        file_name="alertler.csv",
        mime="text/csv",
    )
    excel_buf = io.BytesIO()
    export_df.to_excel(excel_buf, index=False, engine="openpyxl")
    dl2.download_button(
        "📥 Excel endir",
        data=excel_buf.getvalue(),
        file_name="alertler.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
 
    with st.expander("Seçilmiş alert-in tam (xam) JSON-unu gör"):
        if len(fdf):
            options = fdf["alert_id"].tolist()
            chosen = st.selectbox("Alert ID", options)
            raw = fdf.loc[fdf["alert_id"] == chosen, "raw_json"].iloc[0]
            st.json(raw)
 
with tab2:
    if has_clusters and len(fdf) >= 10:
        st.subheader("Cluster ölçüləri")
        sizes = fdf.groupby("cluster_label").size().reset_index(name="say")
        sizes["label"] = sizes["cluster_label"].apply(lambda x: "Noise (-1)" if x == -1 else f"Cluster {int(x)}")
        st.bar_chart(sizes.set_index("label")["say"])
 
        st.subheader("2D vizual xəritə (PCA)")
        X, _ = build_features(fdf)
        coords = PCA(n_components=2, random_state=42).fit_transform(X)
        plot_df = fdf[["alert_name", "severity"]].copy()
        plot_df["x"], plot_df["y"] = coords[:, 0], coords[:, 1]
        plot_df["cluster"] = fdf["cluster_label"].astype(str)
        fig = px.scatter(plot_df, x="x", y="y", color="cluster", hover_data=["alert_name", "severity"])
        st.plotly_chart(fig, use_container_width=True)
 
        st.subheader("Cluster üzrə ən tipik alert adı")
        top_per_cluster = (
            fdf.groupby("cluster_label")["alert_name"]
            .agg(lambda s: s.value_counts().idxmax() if len(s) else "—")
            .reset_index()
            .rename(columns={"alert_name": "ən_çox_rast_gəlinən_alert"})
        )
        st.dataframe(top_per_cluster, use_container_width=True)
    else:
        st.info("Cluster nəticələri göstərilməsi üçün ən azı 10 alert və bir təlim dövrü lazımdır.")
 
with tab3:
    with get_conn() as conn:
        meta = pd.read_sql_query("SELECT * FROM model_meta ORDER BY trained_at DESC LIMIT 20", conn)
    if meta.empty:
        st.info("Model hələ heç vaxt train olunmayıb. `python train.py` ilə əl ilə işə sala bilərsiniz.")
    else:
        st.dataframe(meta, use_container_width=True)
        st.line_chart(meta.set_index("trained_at")[["n_clusters", "n_noise"]].iloc[::-1])
 
with tab4:
    st.subheader("Həftəlik anomaliya hesabatı")
    st.caption("Müdirə göstərmək/email ilə göndərmək üçün - diqqət tələb edən alertləri seç, Word sənədi kimi yüklə.")
 
    n_days = st.slider("Neçə günü əhatə etsin", min_value=1, max_value=30, value=7)
    week_end_ms = now_ms_for_kpi
    week_start_ms = now_ms_for_kpi - n_days * 24 * 60 * 60 * 1000
    week_df = df[(df["creation_time"] >= week_start_ms) & (df["creation_time"] <= week_end_ms)].copy()
 
    anomalies = week_df[week_df["is_anomaly"] == 1].copy()
    anomalies = anomalies.sort_values("creation_dt", ascending=False)
 
    k1, k2, k3 = st.columns(3)
    k1.metric(f"Son {n_days} gündə cəmi alert", len(week_df))
    k2.metric("Anomaliya kandidatı", len(anomalies))
    k3.metric("Bunlardan unikal (noise)", int((week_df["cluster_label"] == -1).sum()))
 
    if anomalies.empty:
        st.info("Bu dövrdə anomaliya kandidatı tapılmadı (nə unikal, nə də yüksək severity alert var).")
    else:
        st.markdown("**Hesabata daxil etmək istədiyin alertləri seç** (defolt olaraq hamısı seçilib):")
        edit_cols = ["alert_id", "creation_dt", "severity", "alert_name", "category", "host_name", "username", "anomaly_reason"]
        edit_cols = [c for c in edit_cols if c in anomalies.columns]
        edit_df = anomalies[edit_cols].copy()
        edit_df.insert(0, "Daxil et", True)
 
        edited = st.data_editor(
            edit_df,
            use_container_width=True,
            height=400,
            disabled=[c for c in edit_cols],
            column_config={"Daxil et": st.column_config.CheckboxColumn(default=True)},
            key="anomaly_editor",
        )
 
        selected_mask = edited["Daxil et"].values
        selected_anomalies = anomalies.loc[selected_mask].copy()
        st.caption(f"{len(selected_anomalies)} / {len(anomalies)} alert hesabata daxil ediləcək")
 
        if st.button("📄 Word hesabatı yarat", type="primary", disabled=selected_anomalies.empty):
            week_start_str = pd.to_datetime(week_start_ms, unit="ms").strftime("%Y-%m-%d")
            week_end_str = pd.to_datetime(week_end_ms, unit="ms").strftime("%Y-%m-%d")
            docx_bytes = build_weekly_report_docx(
                selected_anomalies,
                week_start=week_start_str,
                week_end=week_end_str,
                total_alerts_week=len(week_df),
                n_clusters=n_clusters,
            )
            st.download_button(
                "⬇️ Hesabatı endir (.docx)",
                data=docx_bytes,
                file_name=f"heftelik_hesabat_{week_end_str}.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
 
with tab5:
    st.subheader("Normalın kənarındaki alertlər (bütün vaxt üzrə)")
    st.caption(
        "Bu tab, vaxt aralığı ilə məhdudlaşmadan (sidebar-dakı filtrlər tətbiq olunur) - "
        "modelin 'unikal' (heç bir qrupa uyğun gəlməyən) saydığı və ya yüksək severity-li "
        "bütün alertləri göstərir."
    )
 
    if not has_clusters:
        st.info("Hələ model train olunmayıb, anomaliya təyin edilə bilmir.")
    else:
        anomalies_all = fdf[fdf["is_anomaly"] == 1].copy()
        anomalies_all = anomalies_all.sort_values("creation_dt", ascending=False)
 
        a1, a2 = st.columns(2)
        a1.metric("Cəmi anomaliya", len(anomalies_all))
        a2.metric("Bunlardan unikal (noise)", int((fdf["cluster_label"] == -1).sum()))
 
        if anomalies_all.empty:
            st.success("Hazırda filtrə uyğun heç bir anomaliya yoxdur.")
        else:
            show_cols_anom = ["alert_id", "creation_dt", "severity", "alert_name", "category",
                               "host_name", "username", "anomaly_reason", "description"]
            show_cols_anom = [c for c in show_cols_anom if c in anomalies_all.columns]
 
            if "analyst_label" not in anomalies_all.columns:
                anomalies_all["analyst_label"] = ""
            anomalies_all["analyst_label"] = anomalies_all["analyst_label"].fillna("")
 
            st.markdown(
                "**Hər alert üçün öz rəyini yaz** (sağdaki sütunda) - bu, gələcəkdə "
                "modeli daha ağıllı etmək üçün label-lənmiş data yaradır:"
            )
            edit_cols_anom = ["id"] + show_cols_anom + ["analyst_label"]
            edit_df_anom = anomalies_all[edit_cols_anom].copy()
 
            edited_anom = st.data_editor(
                edit_df_anom,
                use_container_width=True,
                height=520,
                column_order=show_cols_anom + ["analyst_label"],
                disabled=show_cols_anom,
                column_config={
                    "analyst_label": st.column_config.SelectboxColumn(
                        "Analyst rəyi",
                        options=["", "True Positive", "False Positive", "Investigating"],
                        width="medium",
                    )
                },
                key="analyst_label_editor",
            )
 
            if st.button("💾 Analyst rəylərini saxla", type="primary"):
                id_to_label = dict(zip(edited_anom["id"], edited_anom["analyst_label"]))
                save_analyst_labels(id_to_label)
                n_labeled = sum(1 for v in id_to_label.values() if v)
                st.success(f"Saxlanıldı - {n_labeled} alert üçün rəy yazıldı.")
 
            adl1, adl2 = st.columns(2)
            anom_export = anomalies_all[show_cols_anom + ["analyst_label"]]
            adl1.download_button(
                "📥 CSV endir (anomaliyalar)",
                data=anom_export.to_csv(index=False).encode("utf-8-sig"),
                file_name="anomaliyalar.csv",
                mime="text/csv",
            )
            anom_excel_buf = io.BytesIO()
            anom_export.to_excel(anom_excel_buf, index=False, engine="openpyxl")
            adl2.download_button(
                "📥 Excel endir (anomaliyalar)",
                data=anom_excel_buf.getvalue(),
                file_name="anomaliyalar.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
with tab6:
    st.subheader("Vaxt üzrə trendlər")
    st.caption("Sidebar-dakı filtrlər tətbiq olunur.")
 
    if fdf.empty:
        st.info("Göstəriləcək data yoxdur.")
    else:
        daily = fdf.copy()
        daily["gün"] = daily["creation_dt"].dt.date
        per_day = daily.groupby("gün").size().reset_index(name="alert_sayı")
        st.markdown("**Günlük alert sayı**")
        st.line_chart(per_day.set_index("gün")["alert_sayı"])
 
        st.markdown("**Severity-yə görə günlük paylanma**")
        sev_daily = daily.groupby(["gün", "severity"]).size().reset_index(name="say")
        sev_pivot = sev_daily.pivot(index="gün", columns="severity", values="say").fillna(0)
        st.bar_chart(sev_pivot)
 
        if "mitre_attack_tactic" in daily.columns and daily["mitre_attack_tactic"].notna().any():
            st.markdown("**Ən çox rast gəlinən MITRE taktikaları**")
            tactic_counts = (
                daily["mitre_attack_tactic"].dropna().value_counts().head(15)
            )
            st.bar_chart(tactic_counts)
 
        if "category" in daily.columns:
            st.markdown("**Kateqoriyalara görə paylanma**")
            cat_counts = daily["category"].value_counts().head(15)
            st.bar_chart(cat_counts)
 
with tab7:
    st.subheader("Host və User risk reytinqi")
    st.caption("Ən çox anomaliyaya səbəb olan host/user-ları göstərir - sidebar filtrləri tətbiq olunur.")
 
    if fdf.empty or "is_anomaly" not in fdf.columns:
        st.info("Göstəriləcək data yoxdur.")
    else:
        anomaly_df = fdf[fdf["is_anomaly"] == 1]
 
        rc1, rc2 = st.columns(2)
        with rc1:
            st.markdown("**Ən riskli host-lar (anomaliya sayına görə)**")
            host_counts = (
                anomaly_df[anomaly_df["host_name"].notna()]["host_name"]
                .value_counts().head(15)
            )
            if host_counts.empty:
                st.info("Host-a bağlı anomaliya tapılmadı.")
            else:
                st.bar_chart(host_counts)
                st.dataframe(host_counts.reset_index().rename(
                    columns={"index": "host_name", "host_name": "anomaliya_sayı"}
                ), use_container_width=True)
 
        with rc2:
            st.markdown("**Ən riskli user-lər (anomaliya sayına görə)**")
            user_counts = (
                anomaly_df[anomaly_df["username"].notna()]["username"]
                .value_counts().head(15)
            )
            if user_counts.empty:
                st.info("User-ə bağlı anomaliya tapılmadı.")
            else:
                st.bar_chart(user_counts)
                st.dataframe(user_counts.reset_index().rename(
                    columns={"index": "username", "username": "anomaliya_sayı"}
                ), use_container_width=True)