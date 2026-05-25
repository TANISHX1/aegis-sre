import reflex as rx

if hasattr(rx, "el"):
    print("Matches for filter/shadow/glow:")
    for attr in dir(rx.el):
        attr_lower = attr.lower()
        if "filt" in attr_lower or "shadow" in attr_lower or "glow" in attr_lower or "drop" in attr_lower:
            print(f"  rx.el.{attr}")
