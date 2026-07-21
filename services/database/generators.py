"""Synthetic data generators — no external dependencies.

Each generator function returns a realistic value for its field type.
Supports: integer, float, first_name, last_name, email, phone, department,
          salary, product, category, price, address, city, country,
          boolean, text, uuid, date.
"""

import random
import string
import uuid as _uuid
from typing import Any, Dict

# ------------------------------------------------------------------ data pools

_FIRST_NAMES = [
    "Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Hank",
    "Iris", "Jack", "Karen", "Liam", "Mona", "Noel", "Olivia", "Paul",
    "Quinn", "Rita", "Sam", "Tina", "Uma", "Victor", "Wendy", "Xander",
    "Yara", "Zoe", "Aaron", "Bella", "Carlos", "Daisy", "Ethan", "Fiona",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Wilson", "Taylor", "Anderson", "Thomas", "Jackson", "White",
    "Harris", "Martin", "Thompson", "Young", "Allen", "King", "Scott",
    "Green", "Baker", "Adams", "Nelson", "Hill", "Campbell", "Mitchell",
]
_DEPARTMENTS = [
    "Engineering", "Marketing", "Sales", "HR", "Finance", "Operations",
    "Legal", "Product", "Design", "Data Science", "Support", "Research",
]
_PRODUCTS = [
    "Widget Pro", "Gadget X1", "ToolKit Elite", "PowerUnit 500",
    "SmartSensor", "DataLogger", "NanoChip", "FlexBoard", "CoreLink",
    "NetAdapter", "StreamBox", "SignalBoost", "ConnectHub", "RapidDrive",
]
_CATEGORIES = [
    "Electronics", "Hardware", "Software", "Accessories", "Networking",
    "Storage", "Displays", "Peripherals", "Components", "Security",
]
_CITIES = [
    "New York", "London", "Tokyo", "Paris", "Sydney", "Berlin",
    "Toronto", "Singapore", "Dubai", "Amsterdam",
]
_COUNTRIES = [
    "USA", "UK", "Japan", "France", "Australia", "Germany",
    "Canada", "Singapore", "UAE", "Netherlands",
]
_DOMAINS = ["example.com", "mail.net", "corp.org", "work.io", "company.dev"]


# ------------------------------------------------------------------ API

def generate(field_type: str, context: Dict[str, Any] = None) -> Any:
    """Return a synthetic value for *field_type*.

    *context* is the row being built so far (used for email/phone coherence).
    """
    ctx = context or {}
    ft = field_type.lower()

    if ft == "integer" or ft == "int":
        return random.randint(1, 100_000)

    if ft == "float":
        return round(random.uniform(0.0, 10_000.0), 2)

    if ft == "first_name":
        return random.choice(_FIRST_NAMES)

    if ft == "last_name":
        return random.choice(_LAST_NAMES)

    if ft == "email":
        fn = ctx.get("first_name", random.choice(_FIRST_NAMES))
        ln = ctx.get("last_name", random.choice(_LAST_NAMES))
        domain = random.choice(_DOMAINS)
        return f"{fn.lower()}.{ln.lower()}@{domain}"

    if ft == "phone":
        return f"+1-{random.randint(200,999)}-{random.randint(100,999)}-{random.randint(1000,9999)}"

    if ft == "department":
        return random.choice(_DEPARTMENTS)

    if ft == "salary":
        return round(random.uniform(28_000.0, 180_000.0), 2)

    if ft == "product" or ft == "product_name":
        return random.choice(_PRODUCTS)

    if ft == "category":
        return random.choice(_CATEGORIES)

    if ft == "price":
        return round(random.uniform(0.99, 9_999.99), 2)

    if ft == "address":
        num = random.randint(1, 9999)
        street = random.choice(["Main St", "Oak Ave", "Park Rd", "First St", "Elm St"])
        return f"{num} {street}"

    if ft == "city":
        return random.choice(_CITIES)

    if ft == "country":
        return random.choice(_COUNTRIES)

    if ft == "boolean" or ft == "bool":
        return random.choice([True, False])

    if ft == "text":
        length = random.randint(20, 80)
        words = []
        while sum(len(w) for w in words) < length:
            words.append("".join(random.choices(string.ascii_lowercase, k=random.randint(3, 8))))
        return " ".join(words)[:length]

    if ft == "uuid":
        return str(_uuid.uuid4())

    if ft == "date":
        y = random.randint(2010, 2025)
        m = random.randint(1, 12)
        d = random.randint(1, 28)
        return f"{y:04d}-{m:02d}-{d:02d}"

    # fallback
    return f"val_{random.randint(1, 9999)}"
