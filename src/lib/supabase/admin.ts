import { createClient } from "@supabase/supabase-js";
import { getSupabaseUrl } from "@/lib/supabase/public-env";
import { getSupabaseServiceRoleKey } from "@/lib/supabase/private-env";

export function createAdminClient() {
  return createClient(
    getSupabaseUrl(),
    getSupabaseServiceRoleKey(),
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    }
  );
}
