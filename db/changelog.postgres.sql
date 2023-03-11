-- liquibase formatted sql
-- changeset jcbbb:1
CREATE TABLE "users" (
  "id" integer GENERATED BY DEFAULT AS IDENTITY NOT NULL,
  "first_name" varchar(255) NOT NULL,
  "last_name" varchar(255) NOT NULL,
  "email" varchar(255),
  "email_verified" boolean DEFAULT FALSE,
  "phone" varchar(255),
  "phone_verified" boolean DEFAULT FALSE,
  "password" varchar(255) NOT NULL,
  "verified" boolean DEFAULT FALSE,
  "created_at" timestamp with time zone DEFAULT NOW() NOT NULL,
  "picture" varchar(255) NOT NULL,
  CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "sessions" (
  "id" uuid DEFAULT gen_random_uuid () NOT NULL,
  "active" boolean DEFAULT TRUE,
  "ip" inet,
  "expires_at" timestamp with time zone NOT NULL,
  "created_at" timestamp with time zone DEFAULT NOW() NOT NULL,
  "user_id" integer NOT NULL,
  CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "scopes" (
  "id" integer GENERATED BY DEFAULT AS IDENTITY NOT NULL,
  "key" varchar(255) NOT NULL UNIQUE,
  "icon_uri" varchar(255),
  CONSTRAINT "permissions_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "scope_translations" (
  "scope_id" integer NOT NULL,
  "lang" varchar(255) NOT NULL,
  "description" varchar(255) NOT NULL
);

CREATE TABLE "clients" (
  "id" uuid DEFAULT gen_random_uuid () NOT NULL,
  "name" varchar(255) NOT NULL,
  "secret" varchar(255) NOT NULL,
  "uri" varchar(255) NOT NULL,
  "logo_uri" varchar(255),
  "tos_uri" varchar(255),
  "policy_uri" varchar(255),
  "redirect_uris" varchar[] NOT NULL,
  "contacts" varchar[] DEFAULT '{}' ::character varying[],
  "token_endpoint_auth_method" varchar(255),
  "grant_types" varchar[] DEFAULT '{}' ::character varying[],
  "response_types" varchar[] DEFAULT '{}' ::character varying[],
  "created_at" timestamp with time zone DEFAULT NOW() NOT NULL,
  CONSTRAINT "clients_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "client_scopes" (
  client_id uuid NOT NULL,
  scope_id integer NOT NULL
);

CREATE TABLE "authorization_requests" (
  "id" integer GENERATED BY DEFAULT AS IDENTITY NOT NULL,
  "redirect_uri" varchar(255) NOT NULL,
  "response_type" varchar(255) NOT NULL,
  "grant_type" varchar(255) NOT NULL CHECK (grant_type IN ('authorization_code', 'refresh_token', 'client_credentials')),
  "code_challenge" varchar(255) NOT NULL,
  "code_challenge_method" varchar(10) NOT NULL,
  "scope" text NOT NULL,
  "state" text NOT NULL,
  "code" integer UNIQUE,
  "client_id" uuid NOT NULL,
  "user_id" integer NOT NULL,
  "created_at" timestamp with time zone DEFAULT NOW() NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  CONSTRAINT "authorization_requests_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "tokens" (
  "id" uuid DEFAULT gen_random_uuid () NOT NULL,
  "type" varchar(255) NOT NULL DEFAULT 'Bearer',
  "sub" integer NOT NULL,
  "authorization_request_id" integer,
  "refresh_token" uuid DEFAULT gen_random_uuid () NOT NULL,
  "client_id" uuid NOT NULL,
  "created_at" timestamp with time zone DEFAULT NOW() NOT NULL,
  CONSTRAINT "tokens_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "scope_translations"
  ADD CONSTRAINT "fk_scope" FOREIGN KEY ("scope_id") REFERENCES "scopes" ("id") ON UPDATE NO action ON DELETE CASCADE;

ALTER TABLE "tokens"
  ADD CONSTRAINT "fk_authorization_request" FOREIGN KEY ("authorization_request_id") REFERENCES "authorization_requests" ("id") ON UPDATE NO action ON DELETE CASCADE;

ALTER TABLE "sessions"
  ADD CONSTRAINT "fk_user" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;

ALTER TABLE "client_scopes"
  ADD CONSTRAINT "fk_client" FOREIGN KEY ("client_id") REFERENCES "clients" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;

ALTER TABLE "client_scopes"
  ADD CONSTRAINT "fk_scope" FOREIGN KEY ("scope_id") REFERENCES "scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;

CREATE INDEX "idx_sessions_user_id" ON sessions ("user_id");

CREATE UNIQUE INDEX "uidx_authorization_requests_granttype_code_redirecturi" ON "authorization_requests" ("grant_type", "code", "redirect_uri");

CREATE UNIQUE INDEX "uidx_users_email" ON users ("email");

CREATE UNIQUE INDEX "uidx_scopetranslations_scopeid_lang" ON "scope_translations" ("scope_id", "lang");

CREATE UNIQUE INDEX "uidx_users_phone" ON users ("phone");

CREATE UNIQUE INDEX "uidx_clientscopes_scopeid_clientid" ON client_scopes ("scope_id", "client_id");

-- rollback DROP TABLE authorization_requests CASCADE;
-- rollback DROP TABLE clients CASCADE;
-- rollback DROP TABLE permissions CASCADE;
-- rollback DROP TABLE "privileges" CASCADE;
-- rollback DROP TABLE sessions CASCADE;
-- rollback DROP TABLE users CASCADE;
