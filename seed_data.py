"""
seed_data.py - Seed canonical examination documents and recipients for CANARYDOCS.

Populates SQLite database with standard demo fixtures:
- Documents:
  * NEET UG 2026 - Confidential Question Paper Subset (Biology)
  * UPSC CSE 2026 - General Studies Paper I Draft
- Recipients:
  * Dr. Rajesh Sharma (NEET-DEMO-042, National High School, Jaipur - Center 241)
  * Prof. Ananya Sen (NEET-DEMO-088, St. Xavier's Academy, Kolkata - Center 109)
  * Dr. Vikramaditya Verma (UPSC-DEMO-103, Central Evaluation Center, New Delhi - Center 012)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

import database
from models import Document, Recipient
import pdf_generator

UPSC_SAMPLE_TEXT = """CONFIDENTIAL - UPSC CIVIL SERVICES EXAMINATION (PRELIMINARY) 2026
GENERAL STUDIES PAPER - I (DRAFT QUESTIONS FOR EVALUATION COMMITTEE)
AUTHORIZED ACCESS ONLY - STRICT COMPLIANCE REQUIRED

SECTION A: POLITY AND GOVERNANCE
Q1. With reference to the Finance Commission of India, consider the following statements:
1. It is a quasi-judicial body constituted by the President of India under Article 280.
2. The recommendations made by the Finance Commission are binding on the Union Government.
Which of the statements given above is/are correct?
(a) 1 only
(b) 2 only
(c) Both 1 and 2
(d) Neither 1 nor 2

Q2. Consider the following pairs regarding Constitutional Amendments:
1. 42nd Amendment Act : Added words Socialist, Secular, and Integrity to Preamble
2. 44th Amendment Act : Substituted Internal Disturbance with Armed Rebellion
3. 86th Amendment Act : Inserted Article 21A (Right to Education)
Which of the pairs given above are correctly matched?
(a) 1 and 2 only
(b) 2 and 3 only
(c) 1, 2 and 3
(d) 1 and 3 only

SECTION B: ENVIRONMENT AND ECOLOGY
Q3. Which of the following protected areas are designated as UNESCO World Heritage Sites in India?
1. Kaziranga National Park
2. Keoladeo National Park
3. Manas Wildlife Sanctuary
Select the correct answer using the code given below:
(a) 1 and 2 only
(b) 2 and 3 only
(c) 1 and 3 only
(d) 1, 2 and 3

END OF DRAFT QUESTIONS - UPSC CONFIDENTIAL PROTOCOL
"""


def seed_database(
    db_path: Optional[Union[str, Path]] = None,
    force: bool = False,
) -> dict:
    """Seed the database with standard canary fixtures.

    Args:
        db_path: Optional custom path to SQLite database.
        force: If True, clear existing tables before seeding.

    Returns:
        Dictionary summarizing seeded documents and recipients.
    """
    database.init_db(db_path=db_path)

    if force:
        database.clear_all_tables(db_path=db_path)

    # 1. Documents
    docs_to_seed = [
        {
            "name": "NEET UG 2026 - Confidential Question Paper Subset (Biology)",
            "type": "Question Paper",
            "text": pdf_generator.create_demo_neet_document().original_text.strip(),
        },
        {
            "name": "UPSC CSE 2026 - General Studies Paper I Draft",
            "type": "Examination Draft",
            "text": UPSC_SAMPLE_TEXT.strip(),
        },
    ]

    existing_docs = {d.document_name: d for d in database.list_documents(db_path=db_path)}
    created_docs = []

    for item in docs_to_seed:
        if item["name"] in existing_docs:
            created_docs.append(existing_docs[item["name"]])
        else:
            doc = database.create_document(
                document_name=item["name"],
                document_type=item["type"],
                original_text=item["text"],
                db_path=db_path,
            )
            created_docs.append(doc)

    # 2. Recipients
    recipients_to_seed = [
        {
            "name": "Dr. Rajesh Sharma",
            "uid": "NEET-DEMO-042",
            "center": "National High School, Jaipur - Center 241",
        },
        {
            "name": "Prof. Ananya Sen",
            "uid": "NEET-DEMO-088",
            "center": "St. Xavier's Academy, Kolkata - Center 109",
        },
        {
            "name": "Dr. Vikramaditya Verma",
            "uid": "UPSC-DEMO-103",
            "center": "Central Evaluation Center, New Delhi - Center 012",
        },
    ]

    created_recipients = []
    for item in recipients_to_seed:
        existing = database.get_recipient_by_uid(item["uid"], db_path=db_path)
        if existing:
            created_recipients.append(existing)
        else:
            rec = database.create_recipient(
                recipient_uid=item["uid"],
                name=item["name"],
                center=item["center"],
                db_path=db_path,
            )
            created_recipients.append(rec)

    return {
        "documents": created_docs,
        "recipients": created_recipients,
    }


if __name__ == "__main__":
    result = seed_database(force=False)
    print(f"Seeded {len(result['documents'])} documents and {len(result['recipients'])} recipients.")
