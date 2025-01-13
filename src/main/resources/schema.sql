create table if not exists t_user
(
    id         int primary key,
    c_username varchar not null unique,
    c_password varchar not null
);

create table if not exists t_user_authority
(
    id          serial primary key,
    id_user     int     not null references t_user (id),
    c_authority varchar not null
);

create table if not exists t_deactivated_token
(
    id           uuid primary key,
    c_keep_until timestamp not null check ( c_keep_until > now() )
);