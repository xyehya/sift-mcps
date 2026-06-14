# Supabase RLS checklist

For every case-scoped table:

- [ ] `ALTER TABLE table_name ENABLE ROW LEVEL SECURITY;`
- [ ] `SELECT` policy checks case membership and role.
- [ ] `INSERT` policy uses `WITH CHECK` for `case_id` and allowed role.
- [ ] `UPDATE` policy uses both `USING` and `WITH CHECK`.
- [ ] `DELETE` policy is absent by default or restricted to explicit admin/lead paths.
- [ ] Policies do not use `USING (true)` or broad `auth.uid() IS NOT NULL` for sensitive data.
- [ ] Service-role use is restricted to backend/worker code and followed by explicit authorization checks.
- [ ] Storage object paths include `case_id` and are covered by bucket policies.
- [ ] Realtime channels are case-scoped and do not leak other case events.

Example policy shape:

```sql
CREATE POLICY "case members can read findings"
ON findings
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1
    FROM case_members cm
    WHERE cm.case_id = findings.case_id
      AND cm.user_id = auth.uid()
      AND cm.role IN ('investigator', 'lead')
  )
);
```
