create table if not exists profile (
  id integer primary key check (id = 1),
  name text not null,
  role text not null,
  bio text not null,
  location text default '',
  email text default '',
  github text default '',
  linkedin text default,
  website text default,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Enable row level security
alter table profile enable row level security;

-- Create policy for public read access
create policy "Public profiles are viewable by everyone" on profile
  for select using (true);

-- Create policy for admin updates
create policy "Admins can update profile" on profile
  for update using (true);