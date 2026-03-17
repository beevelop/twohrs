-- ==========================================
-- MIGRATION 042: Fix profile stat regressions
--
-- Regression from the hardened archive/cleanup RPCs:
-- cleanup_daily_content() stopped disabling the vote triggers before
-- deleting daily votes/comments, so nightly cleanup decremented
-- lifetime upvote counters again after the day had already been archived.
--
-- This migration:
-- 1. Restores trigger disabling during cleanup.
-- 2. Makes days_won syncing idempotent in archive_daily_leaderboard().
-- 3. Repairs stale profile counters from archived history + current live data.
-- ==========================================

CREATE OR REPLACE FUNCTION public.archive_daily_leaderboard()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_berlin_date DATE;
  v_top_post RECORD;
  v_current_count INTEGER;
  v_max_top_posts CONSTANT INTEGER := 20;
  v_top_comments JSONB;
BEGIN
  IF auth.role() IS NOT NULL AND auth.role() <> 'service_role' THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;

  v_berlin_date := (now() AT TIME ZONE 'Europe/Berlin')::date;

  IF NOT EXISTS (SELECT 1 FROM public.posts LIMIT 1) THEN
    RETURN;
  END IF;

  INSERT INTO public.daily_leaderboard
    (date, user_id, rank, total_upvotes, total_posts, best_post_caption, best_post_upvotes)
  SELECT
    v_berlin_date,
    p.user_id,
    ROW_NUMBER() OVER (ORDER BY SUM(p.upvote_count) DESC, COUNT(p.id) ASC)::integer AS rank,
    COALESCE(SUM(p.upvote_count), 0)::integer AS total_upvotes,
    COUNT(p.id)::integer AS total_posts,
    (
      SELECT caption FROM public.posts
      WHERE user_id = p.user_id
      ORDER BY upvote_count DESC
      LIMIT 1
    ) AS best_post_caption,
    MAX(p.upvote_count)::integer AS best_post_upvotes
  FROM public.posts p
  GROUP BY p.user_id
  ORDER BY total_upvotes DESC
  LIMIT 100
  ON CONFLICT (date, user_id) DO UPDATE SET
    rank = EXCLUDED.rank,
    total_upvotes = EXCLUDED.total_upvotes,
    total_posts = EXCLUDED.total_posts,
    best_post_caption = EXCLUDED.best_post_caption,
    best_post_upvotes = EXCLUDED.best_post_upvotes;

  -- Sync from archived history so reruns cannot double-count wins.
  UPDATE public.profiles p
  SET days_won = 0
  WHERE p.days_won <> 0
    AND NOT EXISTS (
      SELECT 1
      FROM public.daily_leaderboard dl
      WHERE dl.user_id = p.id
        AND dl.rank = 1
    );

  UPDATE public.profiles p
  SET days_won = winners.days_won
  FROM (
    SELECT user_id, COUNT(*)::integer AS days_won
    FROM public.daily_leaderboard
    WHERE rank = 1
    GROUP BY user_id
  ) winners
  WHERE p.id = winners.user_id
    AND p.days_won IS DISTINCT FROM winners.days_won;

  SELECT id, user_id, image_url, image_path, caption, upvote_count
  INTO v_top_post
  FROM public.posts
  ORDER BY upvote_count DESC
  LIMIT 1;

  IF v_top_post IS NULL OR v_top_post.upvote_count = 0 THEN
    RETURN;
  END IF;

  SELECT COALESCE(jsonb_agg(
    jsonb_build_object(
      'username', c.username,
      'text', c.text,
      'upvote_count', c.upvote_count
    )
  ), '[]'::jsonb)
  INTO v_top_comments
  FROM (
    SELECT
      pr.username,
      cm.text,
      cm.upvote_count
    FROM public.comments cm
    JOIN public.profiles pr ON pr.id = cm.user_id
    WHERE cm.post_id = v_top_post.id
    ORDER BY cm.upvote_count DESC
    LIMIT 3
  ) c;

  INSERT INTO public.top_posts_all_time
    (date, user_id, image_url, image_path, caption, upvote_count, top_comments)
  VALUES (
    v_berlin_date,
    v_top_post.user_id,
    v_top_post.image_url,
    v_top_post.image_path,
    v_top_post.caption,
    v_top_post.upvote_count,
    v_top_comments
  )
  ON CONFLICT (date) DO UPDATE SET
    user_id = EXCLUDED.user_id,
    image_url = EXCLUDED.image_url,
    image_path = EXCLUDED.image_path,
    caption = EXCLUDED.caption,
    upvote_count = EXCLUDED.upvote_count,
    top_comments = EXCLUDED.top_comments;

  SELECT COUNT(*) INTO v_current_count FROM public.top_posts_all_time;
  IF v_current_count > v_max_top_posts THEN
    DELETE FROM public.top_posts_all_time
    WHERE id = (
      SELECT id FROM public.top_posts_all_time
      WHERE date != v_berlin_date
      ORDER BY upvote_count ASC
      LIMIT 1
    );
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.cleanup_daily_content()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF auth.role() IS NOT NULL AND auth.role() <> 'service_role' THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;

  BEGIN
    DELETE FROM storage.objects
    WHERE bucket_id = 'memes'
      AND name NOT LIKE 'top-posts/%'
      AND name NOT IN (
        SELECT image_path FROM public.top_posts_all_time
        WHERE image_path IS NOT NULL
      );
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Storage cleanup skipped: %', SQLERRM;
  END;

  ALTER TABLE public.votes DISABLE TRIGGER on_vote_change;
  ALTER TABLE public.comment_votes DISABLE TRIGGER on_comment_vote_change;

  BEGIN
    DELETE FROM public.mentions;
    DELETE FROM public.post_hashtags;
    DELETE FROM public.comment_votes;
    DELETE FROM public.comments;
    DELETE FROM public.votes;
    DELETE FROM public.posts;
  EXCEPTION WHEN OTHERS THEN
    ALTER TABLE public.votes ENABLE TRIGGER on_vote_change;
    ALTER TABLE public.comment_votes ENABLE TRIGGER on_comment_vote_change;
    RAISE;
  END;

  ALTER TABLE public.votes ENABLE TRIGGER on_vote_change;
  ALTER TABLE public.comment_votes ENABLE TRIGGER on_comment_vote_change;
END;
$$;

-- days_won should always match archived winners exactly.
UPDATE public.profiles p
SET days_won = 0
WHERE p.days_won <> 0
  AND NOT EXISTS (
    SELECT 1
    FROM public.daily_leaderboard dl
    WHERE dl.user_id = p.id
      AND dl.rank = 1
  );

UPDATE public.profiles p
SET days_won = winners.days_won
FROM (
  SELECT user_id, COUNT(*)::integer AS days_won
  FROM public.daily_leaderboard
  WHERE rank = 1
  GROUP BY user_id
) winners
WHERE p.id = winners.user_id
  AND p.days_won IS DISTINCT FROM winners.days_won;

-- total_posts_created can drift when protected-column fixes blocked increments.
-- Rebuild the guaranteed minimum from archived leaderboard rows plus live posts.
WITH archived_posts AS (
  SELECT user_id, COALESCE(SUM(total_posts), 0)::integer AS archived_total_posts
  FROM public.daily_leaderboard
  GROUP BY user_id
),
live_posts AS (
  SELECT user_id, COUNT(*)::integer AS live_total_posts
  FROM public.posts
  GROUP BY user_id
),
minimum_post_totals AS (
  SELECT
    p.id AS user_id,
    COALESCE(ap.archived_total_posts, 0) + COALESCE(lp.live_total_posts, 0) AS minimum_total_posts
  FROM public.profiles p
  LEFT JOIN archived_posts ap ON ap.user_id = p.id
  LEFT JOIN live_posts lp ON lp.user_id = p.id
)
UPDATE public.profiles p
SET total_posts_created = m.minimum_total_posts
FROM minimum_post_totals m
WHERE p.id = m.user_id
  AND p.total_posts_created < m.minimum_total_posts;

-- total_upvotes_received includes comment votes historically, but only post
-- upvotes are archived. Restore the guaranteed minimum from archived post
-- upvotes plus the still-live post/comment counters for the current session.
WITH archived_post_upvotes AS (
  SELECT user_id, COALESCE(SUM(total_upvotes), 0)::integer AS archived_total_upvotes
  FROM public.daily_leaderboard
  GROUP BY user_id
),
live_post_upvotes AS (
  SELECT user_id, COALESCE(SUM(upvote_count), 0)::integer AS live_post_upvotes
  FROM public.posts
  GROUP BY user_id
),
live_comment_upvotes AS (
  SELECT user_id, COALESCE(SUM(upvote_count), 0)::integer AS live_comment_upvotes
  FROM public.comments
  GROUP BY user_id
),
minimum_upvote_totals AS (
  SELECT
    p.id AS user_id,
    COALESCE(apu.archived_total_upvotes, 0)
      + COALESCE(lpu.live_post_upvotes, 0)
      + COALESCE(lcu.live_comment_upvotes, 0) AS minimum_total_upvotes
  FROM public.profiles p
  LEFT JOIN archived_post_upvotes apu ON apu.user_id = p.id
  LEFT JOIN live_post_upvotes lpu ON lpu.user_id = p.id
  LEFT JOIN live_comment_upvotes lcu ON lcu.user_id = p.id
)
UPDATE public.profiles p
SET total_upvotes_received = m.minimum_total_upvotes
FROM minimum_upvote_totals m
WHERE p.id = m.user_id
  AND p.total_upvotes_received < m.minimum_total_upvotes;
