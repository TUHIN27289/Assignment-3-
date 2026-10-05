class BallotValidator:
    """
    Server-side validation foundation for ballot and preference inputs (SR-11).
    Provides structural, data-type, and input sanity verification before persistent processing.
    """

    @staticmethod
    def validate_ballot_structure(data):
        """
        Validates basic structure, required fields, and data types of a ballot submission payload.

        Expected format:
        {
            "election_id": str,
            "preferences": [
                {"candidate_id": str, "rank": int},
                ...
            ]
        }

        Returns:
            dict: {
                "is_valid": bool,
                "errors": list of str,
                "cleaned_data": dict or None
            }
        """
        errors = []

        if data is None:
            return {
                "is_valid": False,
                "errors": ["Ballot data cannot be null."],
                "cleaned_data": None
            }

        if not isinstance(data, dict):
            return {
                "is_valid": False,
                "errors": ["Ballot data must be a JSON object/dictionary."],
                "cleaned_data": None
            }

        # 1. Validate election_id
        election_id = data.get("election_id")
        if election_id is None:
            errors.append("Field 'election_id' is required.")
        elif not isinstance(election_id, str):
            errors.append("Field 'election_id' must be a string.")
        elif not election_id.strip():
            errors.append("Field 'election_id' cannot be empty or whitespace.")

        # 2. Validate preferences
        preferences = data.get("preferences")
        if preferences is None:
            errors.append("Field 'preferences' is required.")
        elif not isinstance(preferences, list):
            errors.append("Field 'preferences' must be a list.")
        elif len(preferences) == 0:
            errors.append("Field 'preferences' cannot be empty.")
        else:
            for idx, item in enumerate(preferences):
                if item is None:
                    errors.append(f"Preference at index {idx} cannot be null.")
                    continue
                if not isinstance(item, dict):
                    errors.append(f"Preference at index {idx} must be an object/dictionary.")
                    continue

                candidate_id = item.get("candidate_id")
                if candidate_id is None:
                    errors.append(f"Preference at index {idx} is missing 'candidate_id'.")
                elif not isinstance(candidate_id, str):
                    errors.append(f"Preference at index {idx} 'candidate_id' must be a string.")
                elif not candidate_id.strip():
                    errors.append(f"Preference at index {idx} 'candidate_id' cannot be empty.")

                rank = item.get("rank")
                if rank is None:
                    errors.append(f"Preference at index {idx} is missing 'rank'.")
                elif not isinstance(rank, int) or isinstance(rank, bool):
                    errors.append(f"Preference at index {idx} 'rank' must be an integer.")
                elif rank < 1:
                    errors.append(f"Preference at index {idx} 'rank' must be a positive integer >= 1.")

        if errors:
            return {
                "is_valid": False,
                "errors": errors,
                "cleaned_data": None
            }

        cleaned_data = {
            "election_id": election_id.strip(),
            "preferences": [
                {
                    "candidate_id": item["candidate_id"].strip(),
                    "rank": item["rank"]
                }
                for item in preferences
            ]
        }

        return {
            "is_valid": True,
            "errors": [],
            "cleaned_data": cleaned_data
        }
