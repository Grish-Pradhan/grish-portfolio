begin;

drop policy if exists "Admins can update profile" on public.profile;
drop policy if exists "Admins can manage projects" on public.projects;
drop policy if exists "Admins can view messages" on public.messages;

commit;