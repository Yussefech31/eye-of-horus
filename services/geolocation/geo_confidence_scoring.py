"""
Evaluates the NLP output and calculates a confidence score.
"""

def score_nlp_location(location_string: str, original_text: str) -> float:
    """
    Returns a confidence score between 0.0 and 1.0 based on the extracted NLP location.
    """
    if not location_string or location_string == "Unknown":
        return 0.0
        
    # If the exact location is matched in the text, it's slightly higher confidence
    # But since current NLP is just regex, we consider any non-Unknown to be a 1.0 
    # for the baseline. However, if the text is extremely short, confidence drops.
    if len(original_text) < 10:
        return 0.4
        
    return 1.0
