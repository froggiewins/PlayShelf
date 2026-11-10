-- Playshelf moderation upgrade.
-- If you already ran supabase-setup.sql before November 2026, paste this whole file into
-- Supabase > SQL Editor and run it once. New setups get it as part of supabase-setup.sql.
-- Everything here runs inside your database. No AI service or API key is needed.

-- ───────────── Settings, word list, blocked links, bans, log ─────────────

create table public.mod_settings (
  id int primary key default 1 check (id = 1),
  auto_hide_reports int not null default 3 check (auto_hide_reports between 1 and 100),
  review_all_uploads boolean not null default false,
  review_new_accounts_hours int not null default 0 check (review_new_accounts_hours between 0 and 720),
  comments_per_5_min int not null default 8 check (comments_per_5_min between 1 and 100)
);
insert into public.mod_settings default values;

-- Words are matched whole, ignoring capitals and number swaps like 5h1t.
-- End a word with * to also catch longer words that start with it (fuck* catches fucking).
create table public.blocked_words (
  word text primary key check (word ~ '^[a-z]+( [a-z]+)*\*?$' and char_length(word) between 2 and 40)
);
insert into public.blocked_words (word) values
  ('fuck*'), ('fck*'), ('shit*'), ('cunt*'), ('bitch*'), ('bastard*'), ('asshole*'), ('dickhead*'),
  ('wanker*'), ('slut*'), ('whore*'), ('porn*'), ('nudes'), ('hentai'), ('xxx'), ('retard*'),
  ('kys'), ('kill yourself'), ('kill urself'), ('go die');

-- Links to these sites can't be posted, in a project link or inside uploaded code.
create table public.blocked_domains (
  domain text primary key check (domain ~ '^[a-z0-9-]+(\.[a-z0-9-]+)+$')
);
insert into public.blocked_domains (domain) values
  ('grabify.link'), ('iplogger.org'), ('iplogger.com'), ('iplogger.ru'), ('2no.co'), ('yip.su'),
  ('ipgrabber.ru'), ('blasze.com'), ('ps3cfw.com'), ('bit.ly'), ('tinyurl.com'), ('is.gd'),
  ('cutt.ly'), ('shorturl.at'), ('rebrand.ly'), ('t.ly');

create table public.bans (
  user_id uuid primary key references auth.users(id) on delete cascade,
  reason text not null default '' check (char_length(reason) <= 200),
  banned_by uuid,
  banned_at timestamptz not null default now()
);

create table public.mod_log (
  id bigint generated always as identity primary key,
  at timestamptz not null default now(),
  moderator uuid,
  action text not null check (char_length(action) <= 40),
  target text not null default '' check (char_length(target) <= 120),
  detail text not null default '' check (char_length(detail) <= 300)
);

create function public.is_banned() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.bans where user_id = auth.uid());
$$;

-- True only while the database itself is making an automatic change (such as hiding a reported post),
-- so the checks below let that change through.
create function public.mod_system() returns boolean
language sql stable as $$
  select coalesce(current_setting('playshelf.system', true), '') = 'on';
$$;

create function public.log_mod(act text, tgt text, info text) returns void
language sql security definer set search_path = public as $$
  insert into public.mod_log (moderator, action, target, detail)
  values (case when public.mod_system() then null else auth.uid() end, left(act, 40), left(coalesce(tgt, ''), 120), left(coalesce(info, ''), 300));
$$;
revoke execute on function public.log_mod(text, text, text) from public, anon, authenticated;

create or replace function public.guard_comment() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not (public.is_admin() or public.mod_system()) then
    raise exception 'Only moderators can change comments.';
  end if;
  new.body := old.body;
  new.author := old.author;
  new.project_id := old.project_id;
  new.created_at := old.created_at;
  return new;
end $$;

-- ───────────── Automatic checks ─────────────

-- Lowercases text and undoes common letter swaps, so "Sh1T" is checked as "shit".
create function public.mod_normalize(t text) returns text
language sql immutable as $$
  select translate(lower(coalesce(t, '')), '01345789@$!|', 'oieastbgasil');
$$;

-- Returns the first blocked word found in the text, or null.
create function public.find_blocked_word(t text) returns text
language sql stable security definer set search_path = public as $$
  select replace(w.word, '*', '') from public.blocked_words w
  where public.mod_normalize(t) ~ ('\m' || replace(replace(w.word, '*', ''), ' ', '\s+')
                                   || case when w.word like '%*' then '' else '\M' end)
  limit 1;
$$;

-- Returns the first blocked site mentioned in the text, or null.
create function public.find_blocked_domain(t text) returns text
language sql stable security definer set search_path = public as $$
  select d.domain from public.blocked_domains d
  where lower(coalesce(t, '')) ~ ('(^|[^a-z0-9.-])([a-z0-9-]+\.)*' || replace(d.domain, '.', '\.') || '([^a-z0-9.-]|$)')
  limit 1;
$$;

create function public.mod_check_text(t text) returns void
language plpgsql stable security definer set search_path = public as $$
declare w text;
begin
  w := public.find_blocked_word(t);
  if w is not null then
    raise exception 'That includes a word that isn''t allowed here ("%"). Change it and try again.', w;
  end if;
end $$;

-- Looks through uploaded code. Returns 'block: reason', 'review: reason' or null.
create function public.scan_html(html text) returns text
language plpgsql stable security definer set search_path = public as $$
declare h text := lower(html); d text;
begin
  if h ~ 'type\s*=\s*["'']?password' then
    return 'block: Uploads can''t ask for passwords. Remove the password box and try again.';
  end if;
  if h ~ '(coinhive|coin-hive|cryptonight|crypto-loot|cryptoloot|webminepool|minero\.cc|monerominer|coinimp)' then
    return 'block: This file contains a cryptocurrency miner, which isn''t allowed.';
  end if;
  d := public.find_blocked_domain(h);
  if d is not null then
    return 'block: This file links to ' || d || ', which isn''t allowed here.';
  end if;
  if h ~ '<form[^>]*action\s*=\s*["'']?\s*(https?:)?//' then
    return 'review: It has a form that sends what people type to another website.';
  end if;
  if h ~ '(top|parent)\s*\.\s*location' then
    return 'review: It tries to change the address of the Playshelf page.';
  end if;
  if h ~ 'eval\s*\(\s*(atob|unescape|decodeuricomponent|string\.fromcharcode)' then
    return 'review: It runs hidden, scrambled code.';
  end if;
  if h ~ '(\\x[0-9a-f]{2}){120}' then
    return 'review: It contains a large block of scrambled code.';
  end if;
  if h ~ 'document\s*\.\s*cookie' or h ~ 'navigator\s*\.\s*sendbeacon' then
    return 'review: It tries to read or send browser data.';
  end if;
  return null;
end $$;

-- ───────────── Projects ─────────────

alter table public.projects
  add column held boolean not null default false,
  add column held_reason text not null default '' check (char_length(held_reason) <= 200);

drop policy "read projects" on public.projects;
create policy "read projects" on public.projects for select
  using ((not hidden and not held) or owner = auth.uid() or public.is_admin());
drop policy "post as yourself" on public.projects;
create policy "post as yourself" on public.projects for insert to authenticated
  with check (owner = auth.uid() and not public.is_banned());

create or replace function public.guard_project() returns trigger
language plpgsql security definer set search_path = public as $$
declare s public.mod_settings; d text; joined timestamptz;
begin
  if tg_op = 'UPDATE' and public.mod_system() then
    return new;
  end if;
  if not public.is_admin() then
    if public.is_banned() then
      raise exception 'Your account has been banned from posting.';
    end if;
    perform public.mod_check_text(concat_ws(' ', new.title, new.tagline, new.description, array_to_string(new.tags, ' ')));
    d := public.find_blocked_domain(new.url);
    if d is not null then
      raise exception 'Links to % aren''t allowed. If it''s a short link, post the full address instead.', d;
    end if;
  end if;
  if tg_op = 'INSERT' then
    new.created_at := now();
    new.updated_at := now();
    if not public.is_admin() then
      new.hidden := false;
      new.held := false;
      new.held_reason := '';
      if (select count(*) from public.projects
          where owner = auth.uid() and created_at > now() - interval '1 hour') >= 10 then
        raise exception 'You have posted 10 projects in the last hour. Try again later.';
      end if;
      select * into s from public.mod_settings where id = 1;
      select created_at into joined from auth.users where id = auth.uid();
      if s.review_new_accounts_hours > 0 and joined > now() - make_interval(hours => s.review_new_accounts_hours) then
        new.held := true;
        new.held_reason := 'New accounts wait for a moderator before their posts go live.';
      end if;
    end if;
  else
    new.owner := old.owner;
    new.created_at := old.created_at;
    new.updated_at := now();
    if not public.is_admin() then
      new.hidden := old.hidden;
      new.held := old.held;
      new.held_reason := old.held_reason;
    end if;
  end if;
  return new;
end $$;

-- ───────────── Uploaded files ─────────────

drop policy "add own file" on public.project_files;
create policy "add own file" on public.project_files for insert to authenticated
  with check (not public.is_banned() and exists (select 1 from public.projects p where p.id = project_id and p.owner = auth.uid()));

create function public.guard_file() returns trigger
language plpgsql security definer set search_path = public as $$
declare r text; s public.mod_settings;
begin
  if public.is_admin() then return new; end if;
  if public.is_banned() then raise exception 'Your account has been banned from posting.'; end if;
  r := public.scan_html(new.html);
  if r like 'block: %' then
    raise exception '%', substr(r, 8);
  end if;
  select * into s from public.mod_settings where id = 1;
  if r is null and s.review_all_uploads then
    r := 'review: Every upload is checked by a moderator before it goes live.';
  end if;
  if r is not null then
    perform set_config('playshelf.system', 'on', true);
    update public.projects set held = true, held_reason = substr(r, 9) where id = new.project_id;
    perform set_config('playshelf.system', 'off', true);
  end if;
  return new;
end $$;
create trigger guard_file before insert or update on public.project_files
for each row execute function public.guard_file();

-- ───────────── Comments and names ─────────────

drop policy "comment as yourself" on public.comments;
create policy "comment as yourself" on public.comments for insert to authenticated
  with check (author = auth.uid() and not public.is_banned());

create function public.guard_new_comment() returns trigger
language plpgsql security definer set search_path = public as $$
declare s public.mod_settings;
begin
  new.hidden := false;
  if public.is_admin() then return new; end if;
  if public.is_banned() then raise exception 'Your account has been banned from commenting.'; end if;
  perform public.mod_check_text(new.body);
  if public.find_blocked_domain(new.body) is not null then
    raise exception 'That comment links to a site that isn''t allowed here.';
  end if;
  select * into s from public.mod_settings where id = 1;
  if (select count(*) from public.comments where author = auth.uid()
      and created_at > now() - interval '5 minutes') >= s.comments_per_5_min then
    raise exception 'You''re commenting very fast. Wait a few minutes and try again.';
  end if;
  if exists (select 1 from public.comments where author = auth.uid()
             and lower(body) = lower(new.body) and created_at > now() - interval '1 hour') then
    raise exception 'You already posted that comment.';
  end if;
  return new;
end $$;
create trigger guard_new_comment before insert on public.comments
for each row execute function public.guard_new_comment();

create function public.guard_profile() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    perform public.mod_check_text(new.name);
  end if;
  return new;
end $$;
create trigger guard_profile before insert or update on public.profiles
for each row execute function public.guard_profile();

drop policy "like as yourself" on public.likes;
create policy "like as yourself" on public.likes for insert to authenticated
  with check (user_id = auth.uid() and not public.is_banned());

-- ───────────── Reports ─────────────

alter table public.reports
  add column comment_id uuid references public.comments(id) on delete cascade,
  add column note text not null default '' check (char_length(note) <= 300),
  add column status text not null default 'open' check (status in ('open', 'dismissed', 'resolved'));

-- One report per person for each project or comment.
delete from public.reports a using public.reports b
  where a.reporter = b.reporter and a.project_id = b.project_id and a.comment_id is null and b.comment_id is null
  and a.created_at > b.created_at;
create unique index reports_once on public.reports
  (reporter, project_id, coalesce(comment_id, '00000000-0000-0000-0000-000000000000'::uuid));

drop policy "report as yourself" on public.reports;
create policy "report as yourself" on public.reports for insert to authenticated
  with check (reporter = auth.uid() and not public.is_banned());
create policy "see own reports" on public.reports for select to authenticated
  using (reporter = auth.uid());
create policy "moderators update reports" on public.reports for update to authenticated
  using (public.is_admin()) with check (true);
create policy "moderators delete reports" on public.reports for delete to authenticated
  using (public.is_admin());

-- Counts reports and hides the post or comment once enough different people report it.
create function public.after_report() returns trigger
language plpgsql security definer set search_path = public as $$
declare n int; s public.mod_settings;
begin
  if (select count(*) from public.reports where reporter = new.reporter
      and created_at > now() - interval '1 hour') > 20 then
    raise exception 'You''ve sent a lot of reports this hour. Try again later.';
  end if;
  select * into s from public.mod_settings where id = 1;
  select count(*) into n from public.reports
    where project_id = new.project_id and status = 'open'
    and comment_id is not distinct from new.comment_id;
  if n >= s.auto_hide_reports then
    perform set_config('playshelf.system', 'on', true);
    if new.comment_id is null then
      update public.projects set held = true,
        held_reason = 'Hidden automatically after ' || n || ' reports. A moderator will check it.'
      where id = new.project_id and not held;
      if found then perform public.log_mod('auto-hid project', new.project_id, n || ' reports'); end if;
    else
      update public.comments set hidden = true where id = new.comment_id and not hidden;
      if found then perform public.log_mod('auto-hid comment', new.comment_id::text, n || ' reports'); end if;
    end if;
    perform set_config('playshelf.system', 'off', true);
  end if;
  return new;
end $$;
create trigger after_report after insert on public.reports
for each row execute function public.after_report();

-- ───────────── Moderator actions ─────────────

-- Bans someone. With wipe = true it also deletes everything they've posted.
create function public.ban_user(target uuid, why text, wipe boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only moderators can ban people.'; end if;
  if exists (select 1 from public.admins where user_id = target) then
    raise exception 'Moderators can''t be banned. Remove them from the admins table first.';
  end if;
  insert into public.bans (user_id, reason, banned_by) values (target, left(coalesce(why, ''), 200), auth.uid())
    on conflict (user_id) do update set reason = excluded.reason, banned_by = excluded.banned_by, banned_at = now();
  if wipe then
    delete from public.projects where owner = target;
    delete from public.comments where author = target;
    delete from public.likes where user_id = target;
  end if;
  update public.reports set status = 'resolved' where status = 'open' and (
    project_id in (select id from public.projects where owner = target)
    or comment_id in (select id from public.comments where author = target));
  perform public.log_mod(case when wipe then 'banned and wiped' else 'banned' end, target::text, why);
end $$;

create function public.unban_user(target uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only moderators can unban people.'; end if;
  delete from public.bans where user_id = target;
  perform public.log_mod('unbanned', target::text, '');
end $$;

-- Writes a log line for an action a moderator took from the website.
create function public.mod_note(act text, tgt text, info text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only moderators can write to the log.'; end if;
  perform public.log_mod(act, tgt, info);
end $$;

grant execute on function public.ban_user(uuid, text, boolean), public.unban_user(uuid), public.mod_note(text, text, text) to authenticated;
grant execute on function public.find_blocked_word(text), public.find_blocked_domain(text) to anon, authenticated;

-- ───────────── Who can see and change what ─────────────

alter table public.mod_settings    enable row level security;
alter table public.blocked_words   enable row level security;
alter table public.blocked_domains enable row level security;
alter table public.bans            enable row level security;
alter table public.mod_log         enable row level security;

create policy "read settings" on public.mod_settings for select using (true);
create policy "moderators change settings" on public.mod_settings for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

create policy "read word list" on public.blocked_words for select using (true);
create policy "moderators add words" on public.blocked_words for insert to authenticated with check (public.is_admin());
create policy "moderators remove words" on public.blocked_words for delete to authenticated using (public.is_admin());

create policy "read blocked sites" on public.blocked_domains for select using (true);
create policy "moderators add sites" on public.blocked_domains for insert to authenticated with check (public.is_admin());
create policy "moderators remove sites" on public.blocked_domains for delete to authenticated using (public.is_admin());

create policy "see own ban or all as moderator" on public.bans for select to authenticated
  using (user_id = auth.uid() or public.is_admin());

create policy "moderators read log" on public.mod_log for select to authenticated using (public.is_admin());

grant select on public.mod_settings, public.blocked_words, public.blocked_domains to anon, authenticated;
grant update on public.mod_settings to authenticated;
grant insert, delete on public.blocked_words, public.blocked_domains to authenticated;
grant select on public.bans, public.mod_log to authenticated;
grant update, delete on public.reports to authenticated;
grant select on public.reports to authenticated;
