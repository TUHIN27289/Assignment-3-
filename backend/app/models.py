import sqlite3

class Voter:
    """Model helper representing a voter in the electoral roll."""

    @staticmethod
    def create(conn, voter_identifier, is_eligible=True, has_voted=False, voted_at=None):
        """Inserts a new voter record into the database."""
        cursor = conn.cursor()
        
        if isinstance(conn, sqlite3.Connection):
            query = """
                INSERT INTO voters (voter_identifier, is_eligible, has_voted, voted_at)
                VALUES (?, ?, ?, ?)
            """
            cursor.execute(query, (voter_identifier, 1 if is_eligible else 0, 1 if has_voted else 0, voted_at))
            voter_id = cursor.lastrowid
        else:
            query = """
                INSERT INTO voters (voter_identifier, is_eligible, has_voted, voted_at)
                VALUES (%s, %s, %s, %s)
                RETURNING id;
            """
            cursor.execute(query, (voter_identifier, is_eligible, has_voted, voted_at))
            voter_id = cursor.fetchone()[0]
            
        conn.commit()
        return voter_id

    @staticmethod
    def get_by_identifier(conn, voter_identifier):
        """Retrieves a voter record by voter identifier."""
        cursor = conn.cursor()
        if isinstance(conn, sqlite3.Connection):
            query = "SELECT id, voter_identifier, is_eligible, has_voted, voted_at FROM voters WHERE voter_identifier = ?"
            cursor.execute(query, (voter_identifier,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "voter_identifier": row["voter_identifier"],
                    "is_eligible": bool(row["is_eligible"]),
                    "has_voted": bool(row["has_voted"]),
                    "voted_at": row["voted_at"]
                }
        else:
            query = "SELECT id, voter_identifier, is_eligible, has_voted, voted_at FROM voters WHERE voter_identifier = %s"
            cursor.execute(query, (voter_identifier,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "voter_identifier": row[1],
                    "is_eligible": bool(row[2]),
                    "has_voted": bool(row[3]),
                    "voted_at": row[4]
                }
        return None

    @staticmethod
    def cast_vote_once(conn, voter_identifier):
        """
        Atomically checks eligibility and records that a voter has voted.
        Uses a single conditional SQL UPDATE statement to prevent race conditions.

        Returns a dictionary with:
          - success: bool
          - status: 'SUCCESS' | 'ALREADY_VOTED' | 'INELIGIBLE' | 'NOT_FOUND' | 'INVALID_IDENTIFIER'
          - message: str
          - voter: dict or None
        """
        if not voter_identifier:
            return {
                "success": False,
                "status": "INVALID_IDENTIFIER",
                "message": "Voter identifier is required.",
                "voter": None
            }

        cursor = conn.cursor()
        if isinstance(conn, sqlite3.Connection):
            update_query = """
                UPDATE voters
                SET has_voted = 1, voted_at = CURRENT_TIMESTAMP
                WHERE voter_identifier = ?
                  AND is_eligible = 1
                  AND has_voted = 0;
            """
            cursor.execute(update_query, (voter_identifier,))
            rows_updated = cursor.rowcount
        else:
            update_query = """
                UPDATE voters
                SET has_voted = TRUE, voted_at = NOW()
                WHERE voter_identifier = %s
                  AND is_eligible = TRUE
                  AND has_voted = FALSE
                RETURNING id, voter_identifier, is_eligible, has_voted, voted_at;
            """
            cursor.execute(update_query, (voter_identifier,))
            rows_updated = cursor.rowcount

        conn.commit()

        if rows_updated > 0:
            voter = Voter.get_by_identifier(conn, voter_identifier)
            return {
                "success": True,
                "status": "SUCCESS",
                "message": "Vote recorded successfully.",
                "voter": voter
            }

        # Diagnostic fallback: Determine why 0 rows were updated by the atomic UPDATE
        voter = Voter.get_by_identifier(conn, voter_identifier)
        if voter is None:
            return {
                "success": False,
                "status": "NOT_FOUND",
                "message": "Voter not found in electoral roll.",
                "voter": None
            }
        elif not voter["is_eligible"]:
            return {
                "success": False,
                "status": "INELIGIBLE",
                "message": "Voter is not eligible to vote.",
                "voter": voter
            }
        elif voter["has_voted"]:
            return {
                "success": False,
                "status": "ALREADY_VOTED",
                "message": "Voter has already cast a ballot.",
                "voter": voter
            }

        return {
            "success": False,
            "status": "FAILED",
            "message": "Vote recording failed.",
            "voter": voter
        }
