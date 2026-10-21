"""SR-11: Server-side validation foundation for ballot and preference inputs."""


class BallotValidator:
    """
    Server-side validation foundation for ballot and preference inputs (SR-11).
    Provides structural, data-type, input sanity, and preference-ordering verification.
    """

    @staticmethod
    def validate_preference_order(preferences):
        """
        Validates business rules for candidate preferences:
        1. No duplicate candidate IDs.
        2. No duplicate ranks.
        3. Ranks must form a continuous 1..N sequence starting at 1.

        Args:
            preferences (list): List of dicts, each with 'candidate_id' (str) and 'rank' (int).

        Returns:
            tuple: (is_valid: bool, errors: list of str)
        """
        errors = []
        seen_candidates = set()
        seen_ranks = set()
        ranks = []

        for idx, item in enumerate(preferences):
            cand_id = str(item["candidate_id"]).strip()
            rank = item["rank"]

            if cand_id in seen_candidates:
                errors.append(f"Duplicate candidate ID '{cand_id}' found in preferences.")
            else:
                seen_candidates.add(cand_id)

            if rank in seen_ranks:
                errors.append(f"Duplicate rank '{rank}' found in preferences.")
            else:
                seen_ranks.add(rank)
                ranks.append(rank)

        # Check sequence continuity only if no duplicate ranks exist
        if len(seen_ranks) == len(preferences) and ranks:
            sorted_ranks = sorted(ranks)
            if sorted_ranks[0] != 1:
                errors.append(f"Preference ranks must start at 1. Smallest rank found was {sorted_ranks[0]}.")
            else:
                expected_sequence = list(range(1, len(preferences) + 1))
                if sorted_ranks != expected_sequence:
                    # Find the first missing rank
                    missing_rank = None
                    for exp in expected_sequence:
                        if exp not in sorted_ranks:
                            missing_rank = exp
                            break
                    errors.append(f"Preference ranks must form a continuous sequence starting at 1. Missing rank {missing_rank}.")

        return len(errors) == 0, errors

    @staticmethod
    def validate_ballot_structure(data):
        """
        Validates structure, data types, required fields, and preference ordering rules.

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

        # 2. Validate preferences structure & item data types
        preferences = data.get("preferences")
        has_structural_pref_error = False

        if preferences is None:
            errors.append("Field 'preferences' is required.")
            has_structural_pref_error = True
        elif not isinstance(preferences, list):
            errors.append("Field 'preferences' must be a list.")
            has_structural_pref_error = True
        elif len(preferences) == 0:
            errors.append("Field 'preferences' cannot be empty.")
            has_structural_pref_error = True
        else:
            for idx, item in enumerate(preferences):
                if item is None:
                    errors.append(f"Preference at index {idx} cannot be null.")
                    has_structural_pref_error = True
                    continue
                if not isinstance(item, dict):
                    errors.append(f"Preference at index {idx} must be an object/dictionary.")
                    has_structural_pref_error = True
                    continue

                candidate_id = item.get("candidate_id")
                if candidate_id is None:
                    errors.append(f"Preference at index {idx} is missing 'candidate_id'.")
                    has_structural_pref_error = True
                elif not isinstance(candidate_id, str):
                    errors.append(f"Preference at index {idx} 'candidate_id' must be a string.")
                    has_structural_pref_error = True
                elif not candidate_id.strip():
                    errors.append(f"Preference at index {idx} 'candidate_id' cannot be empty.")
                    has_structural_pref_error = True

                rank = item.get("rank")
                if rank is None:
                    errors.append(f"Preference at index {idx} is missing 'rank'.")
                    has_structural_pref_error = True
                elif not isinstance(rank, int) or isinstance(rank, bool):
                    errors.append(f"Preference at index {idx} 'rank' must be an integer.")
                    has_structural_pref_error = True
                elif rank < 1:
                    errors.append(f"Preference at index {idx} 'rank' must be a positive integer >= 1.")
                    has_structural_pref_error = True

        # 3. If preferences are structurally valid, evaluate preference-ordering business rules
        if not has_structural_pref_error and preferences:
            order_valid, order_errors = BallotValidator.validate_preference_order(preferences)
            if not order_valid:
                errors.extend(order_errors)

        if errors:
            return {
                "is_valid": False,
                "errors": errors,
                "cleaned_data": None
            }

        # Normalize and sort preferences by rank
        cleaned_preferences = sorted(
            [
                {
                    "candidate_id": item["candidate_id"].strip(),
                    "rank": item["rank"]
                }
                for item in preferences
            ],
            key=lambda x: x["rank"]
        )

        cleaned_data = {
            "election_id": election_id.strip(),
            "preferences": cleaned_preferences
        }

        return {
            "is_valid": True,
            "errors": [],
            "cleaned_data": cleaned_data
        }
