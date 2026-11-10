# Playshelf

A website where people upload HTML games and web apps that run right on the site, or post links to projects hosted elsewhere.

## Setup

1. Create a Supabase project and run `supabase-setup.sql` in its SQL Editor.
2. In `index.html`, fill in `SUPABASE_URL` and `SUPABASE_ANON_KEY` near the top of the script.
3. In Supabase, go to Authentication > URL Configuration. Set the Site URL to this site's address and add it to the redirect URLs.
4. Sign in on the site once, then run the last line of `supabase-setup.sql` with your user ID to become a moderator.

Until the keys are filled in, the site runs in practice mode and posts stay in your own browser.

## Upgrading an existing database

If you set up the database before moderation was added, run `supabase-moderation.sql` once in the SQL Editor. New setups don't need it, because `supabase-setup.sql` already includes it.

## Moderation

Everything runs inside the database, so no AI service or API key is needed.

- **Reports:** anyone signed in can report a project or comment once, with a reason and an optional note. When enough different people report something (3 by default), it's hidden until a moderator checks it.
- **Automatic checks:** blocked words in names, titles, descriptions, tags and comments; blocked sites such as IP loggers and link shorteners; uploads that ask for passwords or contain crypto miners are refused; uploads with risky code (forms that send data elsewhere, scrambled code, redirects) wait for a moderator. Posting and commenting are rate-limited.
- **Moderators** see a Moderation button with a queue of everything that needs checking. They can approve, hide, delete, view uploaded code, and ban people (optionally deleting everything they posted). Word lists, blocked sites and settings are edited on the same page, and every action is logged.
