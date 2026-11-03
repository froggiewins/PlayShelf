# Playshelf

A website where people upload HTML games and web apps that run right on the site, or post links to projects hosted elsewhere.

## Setup

1. Create a Supabase project and run `supabase-setup.sql` in its SQL Editor.
2. In `index.html`, fill in `SUPABASE_URL` and `SUPABASE_ANON_KEY` near the top of the script.
3. In Supabase, go to Authentication > URL Configuration. Set the Site URL to this site's address and add it to the redirect URLs.
4. Sign in on the site once, then run the last line of `supabase-setup.sql` with your user ID to become a moderator.

Until the keys are filled in, the site runs in practice mode and posts stay in your own browser.
