"""
Eye of Horus — Statistical Anomaly Detector
Analyzes recent threat volumes against historical baselines to detect 
sudden spikes in cyber threat activity.
"""

import pandas as pd
import numpy as np


def detect_anomalies(df: pd.DataFrame, window_mins: int = 60, z_threshold: float = 2.0) -> dict:
    """
    Detects if the volume of threats in the recent `window_mins` is statistically
    anomalous compared to the preceding baseline.
    """
    if df.empty or "published_at" not in df.columns:
        return {"is_anomalous": False, "reason": "No data"}

    # Ensure datetime index
    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["published_at"]):
        df["published_at"] = pd.to_datetime(df["published_at"], utc=True)
        
    df.set_index("published_at", inplace=True)
    df.sort_index(inplace=True)

    # Bin into 5-minute intervals
    freq = "5min"
    binned = df.resample(freq).size()
    
    if len(binned) < 6: # Need at least 30 mins of data
        return {"is_anomalous": False, "reason": "Insufficient historical data (need 30+ mins)"}

    # Split into baseline and recent window
    recent_cutoff = binned.index[-1] - pd.Timedelta(minutes=window_mins)
    baseline = binned[binned.index < recent_cutoff]
    recent = binned[binned.index >= recent_cutoff]

    if len(baseline) < 3:
        # Not enough baseline data to compute stats
        # Compare against total average as fallback
        mean_vol = binned.mean()
        std_vol = binned.std() if binned.std() > 0 else 1.0
    else:
        mean_vol = baseline.mean()
        std_vol = baseline.std() if baseline.std() > 0 else 1.0

    recent_mean = recent.mean() if not recent.empty else 0

    z_score = (recent_mean - mean_vol) / std_vol

    is_anomalous = z_score > z_threshold

    # Calculate severity breakdown for the recent anomaly window
    if is_anomalous and not recent.empty:
        recent_df = df[df.index >= recent_cutoff]
        severities = recent_df.get("severity", pd.Series(dtype=str)).value_counts().to_dict() if "severity" in recent_df.columns else {}
    else:
        severities = {}

    return {
        "is_anomalous": bool(is_anomalous),
        "z_score": float(z_score),
        "baseline_mean": float(mean_vol),
        "recent_mean": float(recent_mean),
        "severities": severities,
        "reason": f"Activity is {z_score:.1f} standard deviations above baseline" if is_anomalous else "Activity normal"
    }
