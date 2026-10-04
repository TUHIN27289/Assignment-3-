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
