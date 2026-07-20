"""Portal HTTP surface for the Gateway (P4.23 target).

Thin route modules whose only job is: parse -> authorize -> call a custody domain
function -> return a shaped response. They carry ZERO business logic
(OPERATING-MODEL §1/§12, reviewer-enforced).
"""
