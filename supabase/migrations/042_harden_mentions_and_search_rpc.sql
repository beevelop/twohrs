-- ==========================================
-- MIGRATION 042: Harden mentions + hashtag search RPC
--
-- 1. Prevent authenticated users from inserting arbitrary mentions that
--    reference posts/comments they do not own.
-- 2. Restrict search_hashtags() execution to authenticated users and
--    service_role, and re-apply the app-open gate inside the definer RPC.
-- ==========================================

DROP POLICY IF EXISTS "mentions_insert" ON public.mentions;
CREATE POLICY "mentions_insert"
  ON public.mentions FOR INSERT
  TO authenticated
  WITH CHECK (
    public.is_app_open()
    AND mentioning_user_id = auth.uid()
    AND (
      (
        comment_id IS NULL
        AND post_id IS NOT NULL
        AND post_id IN (
          SELECT id FROM public.posts WHERE user_id = auth.uid()
        )
      )
      OR
      (
        comment_id IS NOT NULL
        AND EXISTS (
          SELECT 1
          FROM public.comments c
          WHERE c.id = comment_id
            AND c.user_id = auth.uid()
            AND (post_id IS NULL OR c.post_id = post_id)
        )
      )
    )
  );

CREATE OR REPLACE FUNCTION public.search_hashtags(query_prefix TEXT)
RETURNS TABLE(hashtag TEXT, post_count BIGINT)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF auth.role() IS NOT NULL THEN
    IF auth.role() NOT IN ('authenticated', 'service_role') THEN
      RAISE EXCEPTION 'Unauthorized';
    END IF;

    IF auth.role() = 'authenticated' AND NOT public.is_app_open() THEN
      RAISE EXCEPTION 'App is closed';
    END IF;
  END IF;

  RETURN QUERY
  SELECT ph.hashtag, COUNT(*) AS post_count
  FROM public.post_hashtags ph
  WHERE ph.hashtag LIKE (
    replace(replace(replace(query_prefix, '\', '\\'), '%', '\%'), '_', '\_') || '%'
  ) ESCAPE '\'
  GROUP BY ph.hashtag
  ORDER BY post_count DESC
  LIMIT 20;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.search_hashtags(TEXT) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.search_hashtags(TEXT) TO authenticated, service_role;
