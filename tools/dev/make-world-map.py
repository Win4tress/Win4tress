"""Builds ui/src/lib/world-map.json: every country as an SVG path, keyed by its
ISO 3166 alpha-2 code (as DB-IP reports countries), for the Traffic map.

Source: Natural Earth 1:110m Admin 0 countries (public domain), projected with
the Equal Earth projection and rounded to a tenth of a pixel. Antarctica is
left out. Run it again only to change the map:

    python -I tools/dev/make-world-map.py [path/to/ne_110m_admin_0_countries.geojson]

Without a path it downloads the file from Natural Earth's repository.
"""

import json
import math
import sys
import urllib.request
from pathlib import Path

URL = (
    "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/"
    "v5.1.2/geojson/ne_110m_admin_0_countries.geojson"
)
OUT = Path(__file__).resolve().parents[2] / "ui" / "src" / "lib" / "world-map.json"
WIDTH = 1000

# Equal Earth (Šavrič, Patterson, Jenny 2018).
A1, A2, A3, A4 = 1.340264, -0.081106, 0.000893, 0.003796
M = math.sqrt(3) / 2


def equal_earth(lon, lat):
    lam, phi = math.radians(lon), math.radians(lat)
    t = math.asin(M * math.sin(phi))
    t2 = t * t
    t6 = t2 * t2 * t2
    x = lam * math.cos(t) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2)))
    y = t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))
    return x, y


# The projection's extent: x at ±180° on the equator, y at ±90°.
X_MAX = equal_earth(180, 0)[0]
Y_MAX = equal_earth(0, 90)[1]
# Antarctica is left out, so the map ends at 60° south.
Y_MIN = equal_earth(0, -60)[1]
SCALE = WIDTH / (2 * X_MAX)
HEIGHT = round((Y_MAX - Y_MIN) * SCALE)


def point(lon, lat):
    x, y = equal_earth(lon, lat)
    return (x + X_MAX) * SCALE, (Y_MAX - y) * SCALE


def ring_path(ring):
    out = []
    last = None
    for lon, lat in ring:
        x, y = point(lon, lat)
        p = (round(x, 1), round(y, 1))
        if p == last:
            continue
        out.append(f"{p[0]:g},{p[1]:g}")
        last = p
    if len(out) < 3:
        return ""
    return "M" + "L".join(out) + "Z"


def main():
    if len(sys.argv) > 1:
        data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    else:
        with urllib.request.urlopen(URL, timeout=60) as r:
            data = json.loads(r.read().decode("utf-8"))
    countries = []
    for f in data["features"]:
        props = f["properties"]
        iso = props.get("ISO_A2_EH") or props.get("ISO_A2")
        if not iso or iso == "-99" or iso == "AQ":
            continue
        geom = f["geometry"]
        polygons = geom["coordinates"] if geom["type"] == "MultiPolygon" else [geom["coordinates"]]
        d = "".join(ring_path(ring) for poly in polygons for ring in poly)
        if d:
            countries.append({"iso": iso, "name": props.get("NAME") or iso, "d": d})
    countries.sort(key=lambda c: c["iso"])
    OUT.write_text(
        json.dumps(
            {
                "source": "Natural Earth 1:110m Admin 0 countries (public domain), Equal Earth projection",
                "width": WIDTH,
                "height": HEIGHT,
                "countries": countries,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    print(f"{len(countries)} countries, {OUT.stat().st_size // 1024} KB -> {OUT}")


if __name__ == "__main__":
    main()
