-- liquibase formatted sql
-- changeset jcbbb:1
CREATE TABLE "users" (
  "id" integer GENERATED BY DEFAULT AS IDENTITY NOT NULL,
  "first_name" varchar(255) NOT NULL,
  "last_name" varchar(255) NOT NULL,
  "email" varchar(255),
  "email_verified" boolean DEFAULT FALSE,
  "phone" varchar(255),
  "phone_verified" varchar(255) DEFAULT 'false',
  "password" varchar(255) NOT NULL,
  "verified" boolean DEFAULT FALSE,
  "created_at" timestamp with time zone DEFAULT NOW() NOT NULL,
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

CREATE TABLE "permissions" (
  "id" integer GENERATED BY DEFAULT AS IDENTITY NOT NULL,
  "action" varchar(255) NOT NULL,
  "resource" varchar(255) NOT NULL,
  CONSTRAINT "permissions_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "privileges" (
  "id" integer GENERATED BY DEFAULT AS IDENTITY NOT NULL,
  "user_id" integer NOT NULL,
  "permission_id" integer NOT NULL,
  "created_at" timestamp with time zone DEFAULT NOW() NOT NULL,
  CONSTRAINT "privileges_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "clients" (
  "id" uuid DEFAULT gen_random_uuid () NOT NULL,
  "name" varchar(255) NOT NULL,
  "secret" varchar(255) NOT NULL,
  "uri" varchar(255) NOT NULL,
  "scope" text NOT NULL,
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

CREATE TABLE "authorization_requests" (
  "id" integer GENERATED BY DEFAULT AS IDENTITY NOT NULL,
  "redirect_uri" varchar(255) NOT NULL,
  "response_type" varchar(255) NOT NULL,
  "code_challenge" varchar(255) NOT NULL,
  "code_challenge_method" varchar(10) NOT NULL,
  "scope" text NOT NULL,
  "state" text NOT NULL,
  "code" integer,
  "client_id" integer NOT NULL,
  "user_id" integer NOT NULL,
  CONSTRAINT "authorization_requests_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "privileges"
  ADD CONSTRAINT "fk_permission" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE SET NULL;

ALTER TABLE "privileges"
  ADD CONSTRAINT "fk_user" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;

ALTER TABLE "sessions"
  ADD CONSTRAINT "fk_user" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;

CREATE INDEX "idx_privileges_permission_id" ON privileges ("permission_id");

CREATE INDEX "idx_privileges_user_id" ON privileges ("user_id");

CREATE INDEX "idx_sessions_user_id" ON sessions ("user_id")
  -- rollback DROP TABLE authorization_requests CASCADE;
  -- rollback DROP TABLE clients CASCADE;
  -- rollback DROP TABLE permissions CASCADE;
  -- rollback DROP TABLE "privileges" CASCADE;
  -- rollback DROP TABLE sessions CASCADE;
  -- rollback DROP TABLE users CASCADE;
