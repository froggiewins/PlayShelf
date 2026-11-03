-- Playshelf database. Paste this whole file into Supabase > SQL Editor and run it once.
-- Afterwards make yourself a moderator (see the last line of this file).

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 30)
);

create table public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

create table public.projects (
  id text primary key check (id ~ '^[a-zA-Z0-9-]{1,40}$'),
  owner uuid not null default auth.uid() references auth.users(id) on delete cascade,
  source text not null default 'link' check (source in ('link', 'html')),
  html_size int not null default 0,
  url text unique check (url is null or (url ~ '^https://' and char_length(url) <= 500)),
  title text not null check (char_length(title) between 1 and 60),
  tagline text not null default '' check (char_length(tagline) <= 110),
  description text not null default '' check (char_length(description) <= 2000),
  kind text not null default 'game' check (kind in ('game', 'app')),
  tags text[] not null default '{}' check (cardinality(tags) <= 5),
  inputs text[] not null default '{}' check (inputs <@ array['keyboard', 'mouse', 'touch', 'gamepad']),
  multiplayer boolean not null default false,
  palette int not null default 0 check (palette between 0 and 7),
  pattern int not null default 0 check (pattern between 0 and 5),
  hidden boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((source = 'link') = (url is not null))
);

create table public.likes (
  project_id text not null references public.projects(id) on delete cascade,
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  primary key (project_id, user_id)
);

create table public.comments (
  id uuid primary key default gen_random_uuid(),
  project_id text not null references public.projects(id) on delete cascade,
  author uuid not null default auth.uid() references auth.users(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 600),
  hidden boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.plays (
  project_id text primary key references public.projects(id) on delete cascade,
  count bigint not null default 0
);

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  project_id text not null references public.projects(id) on delete cascade,
  reporter uuid not null default auth.uid() references auth.users(id) on delete cascade,
  reason text not null check (char_length(reason) <= 60),
  created_at timestamptz not null default now()
);

-- Only moderators can change owner, hidden or the created date. Also limits posting to 10 an hour.
create function public.guard_project() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.created_at := now();
    new.updated_at := now();
    if not public.is_admin() then
      new.hidden := false;
      if (select count(*) from public.projects
          where owner = auth.uid() and created_at > now() - interval '1 hour') >= 10 then
        raise exception 'You have posted 10 projects in the last hour. Try again later.';
      end if;
    end if;
  else
    new.owner := old.owner;
    new.created_at := old.created_at;
    new.updated_at := now();
    if not public.is_admin() then
      new.hidden := old.hidden;
    end if;
  end if;
  return new;
end $$;
create trigger guard_project before insert or update on public.projects
for each row execute function public.guard_project();

-- Only moderators can hide comments, and comment text can't be rewritten after posting.
create function public.guard_comment() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    raise exception 'Only moderators can change comments.';
  end if;
  new.body := old.body;
  new.author := old.author;
  new.project_id := old.project_id;
  new.created_at := old.created_at;
  return new;
end $$;
create trigger guard_comment before update on public.comments
for each row execute function public.guard_comment();

-- Open counts are changed only through this function, one step at a time.
create function public.bump_play(pid text) returns void
language sql security definer set search_path = public as $$
  insert into public.plays (project_id, count)
  select id, 1 from public.projects where id = pid
  on conflict (project_id) do update set count = public.plays.count + 1;
$$;
grant execute on function public.bump_play(text) to anon, authenticated;

alter table public.profiles enable row level security;
alter table public.admins   enable row level security;
alter table public.projects enable row level security;
alter table public.likes    enable row level security;
alter table public.comments enable row level security;
alter table public.plays    enable row level security;
alter table public.reports  enable row level security;

create policy "names are public" on public.profiles for select using (true);
create policy "set own name" on public.profiles for insert to authenticated with check (id = auth.uid());
create policy "change own name" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

create policy "see own admin row" on public.admins for select to authenticated using (user_id = auth.uid());

create policy "read projects" on public.projects for select
  using (not hidden or owner = auth.uid() or public.is_admin());
create policy "post as yourself" on public.projects for insert to authenticated with check (owner = auth.uid());
create policy "edit own or moderate" on public.projects for update to authenticated
  using (owner = auth.uid() or public.is_admin()) with check (true);
create policy "delete own or moderate" on public.projects for delete to authenticated
  using (owner = auth.uid() or public.is_admin());

create policy "read likes" on public.likes for select using (true);
create policy "like as yourself" on public.likes for insert to authenticated with check (user_id = auth.uid());
create policy "remove own like" on public.likes for delete to authenticated using (user_id = auth.uid());

create policy "read comments" on public.comments for select using (not hidden or public.is_admin());
create policy "comment as yourself" on public.comments for insert to authenticated with check (author = auth.uid());
create policy "moderate comments" on public.comments for update to authenticated using (public.is_admin()) with check (true);
create policy "delete own or moderate comment" on public.comments for delete to authenticated
  using (author = auth.uid() or public.is_admin());

create policy "read open counts" on public.plays for select using (true);

create policy "report as yourself" on public.reports for insert to authenticated with check (reporter = auth.uid());
create policy "moderators read reports" on public.reports for select to authenticated using (public.is_admin());

create table public.project_files (
  project_id text primary key references public.projects(id) on delete cascade,
  html text not null check (char_length(html) <= 2000000)
);
alter table public.project_files enable row level security;
-- Reading goes through the projects rules, so a hidden project's file is hidden too.
create policy "read files of visible projects" on public.project_files for select
  using (exists (select 1 from public.projects p where p.id = project_id));
create policy "add own file" on public.project_files for insert to authenticated
  with check (exists (select 1 from public.projects p where p.id = project_id and p.owner = auth.uid()));
create policy "replace own file" on public.project_files for update to authenticated
  using (exists (select 1 from public.projects p where p.id = project_id and p.owner = auth.uid()));
create policy "delete own file" on public.project_files for delete to authenticated
  using (exists (select 1 from public.projects p where p.id = project_id and p.owner = auth.uid()));

alter publication supabase_realtime add table public.projects, public.likes, public.comments, public.plays;

-- After signing in to your site once, find your user id under Authentication > Users, then run:
-- insert into public.admins (user_id) values ('PASTE-YOUR-USER-ID-HERE');
