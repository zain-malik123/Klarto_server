--
-- PostgreSQL database dump
--

\restrict JRGfM4cWFvMYZeloyhRh5wbmPeMeY5rVyJE45UNH0oMgqQLSQ6wu5FWJnaXPl9Z

-- Dumped from database version 13.23
-- Dumped by pg_dump version 13.23

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: trigger_set_timestamp(); Type: FUNCTION; Schema: public; Owner: klarto_api_user
--

CREATE FUNCTION public.trigger_set_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


ALTER FUNCTION public.trigger_set_timestamp() OWNER TO klarto_api_user;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: activities; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.activities (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    activity_name character varying(255) NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.activities OWNER TO klarto_api_user;

--
-- Name: comments; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.comments (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    todo_id uuid NOT NULL,
    user_id uuid NOT NULL,
    text text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.comments OWNER TO klarto_api_user;

--
-- Name: filters; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.filters (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    query text NOT NULL,
    color text NOT NULL,
    is_favorite boolean DEFAULT false NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.filters OWNER TO klarto_api_user;

--
-- Name: invitations; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.invitations (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    team_id uuid NOT NULL,
    inviter_id uuid NOT NULL,
    invited_user_id uuid,
    email character varying(255) NOT NULL,
    invite_token character varying(255) NOT NULL,
    invite_token_expires_at timestamp with time zone,
    status character varying(50) DEFAULT 'pending'::character varying,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    accepted_at timestamp with time zone
);


ALTER TABLE public.invitations OWNER TO klarto_api_user;

--
-- Name: labels; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.labels (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    color text,
    user_id uuid,
    team_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    is_favorite boolean DEFAULT false NOT NULL
);


ALTER TABLE public.labels OWNER TO klarto_api_user;

--
-- Name: notes; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.notes (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    type character varying(20) DEFAULT 'text'::character varying NOT NULL,
    content text,
    media_url text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    media_base64 text
);


ALTER TABLE public.notes OWNER TO klarto_api_user;

--
-- Name: projects; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.projects (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    owner_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    color character varying(50),
    access_type character varying(20) DEFAULT 'everyone'::character varying NOT NULL,
    team_id uuid,
    is_favorite boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.projects OWNER TO klarto_api_user;

--
-- Name: sub_todos; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.sub_todos (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    todo_id uuid NOT NULL,
    title text NOT NULL,
    is_completed boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    description text,
    due_date date,
    due_time time without time zone,
    priority integer,
    label_id uuid
);


ALTER TABLE public.sub_todos OWNER TO klarto_api_user;

--
-- Name: subscription_plans; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.subscription_plans (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    member_limit integer NOT NULL,
    price numeric(10,2) NOT NULL,
    stripe_price_id character varying(255),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.subscription_plans OWNER TO klarto_api_user;

--
-- Name: team_members; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.team_members (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    team_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role character varying(50) DEFAULT 'member'::character varying NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.team_members OWNER TO klarto_api_user;

--
-- Name: teams; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.teams (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    owner_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.teams OWNER TO klarto_api_user;

--
-- Name: todo_labels; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.todo_labels (
    todo_id uuid NOT NULL,
    label_id uuid NOT NULL
);


ALTER TABLE public.todo_labels OWNER TO klarto_api_user;

--
-- Name: todos; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.todos (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    title text NOT NULL,
    description text,
    due_date timestamp with time zone,
    completed boolean DEFAULT false NOT NULL,
    priority integer DEFAULT 0,
    repeat_rule text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id uuid NOT NULL,
    team_id uuid,
    project_id uuid,
    label_id uuid,
    project_name text,
    due_time text,
    repeat_value text,
    is_completed boolean DEFAULT false
);


ALTER TABLE public.todos OWNER TO klarto_api_user;

--
-- Name: trial_usage; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.trial_usage (
    email character varying(255) NOT NULL,
    used_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.trial_usage OWNER TO klarto_api_user;

--
-- Name: user_subscriptions; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.user_subscriptions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    stripe_customer_id character varying(255),
    stripe_subscription_id character varying(255),
    card_last_four character varying(4),
    card_brand character varying(50),
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_subscriptions OWNER TO klarto_api_user;

--
-- Name: users; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.users (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    is_verified boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    verification_token character varying(255),
    verification_token_expires_at timestamp with time zone,
    password_reset_token character varying(255),
    password_reset_token_expires_at timestamp with time zone,
    profile_picture_base64 text,
    has_completed_onboarding boolean DEFAULT false NOT NULL
);


ALTER TABLE public.users OWNER TO klarto_api_user;

--
-- Name: activities activities_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.activities
    ADD CONSTRAINT activities_pkey PRIMARY KEY (id);


--
-- Name: comments comments_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.comments
    ADD CONSTRAINT comments_pkey PRIMARY KEY (id);


--
-- Name: filters filters_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.filters
    ADD CONSTRAINT filters_pkey PRIMARY KEY (id);


--
-- Name: labels labels_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.labels
    ADD CONSTRAINT labels_pkey PRIMARY KEY (id);


--
-- Name: notes notes_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.notes
    ADD CONSTRAINT notes_pkey PRIMARY KEY (id);


--
-- Name: sub_todos sub_todos_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.sub_todos
    ADD CONSTRAINT sub_todos_pkey PRIMARY KEY (id);


--
-- Name: subscription_plans subscription_plans_name_key; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.subscription_plans
    ADD CONSTRAINT subscription_plans_name_key UNIQUE (name);


--
-- Name: subscription_plans subscription_plans_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.subscription_plans
    ADD CONSTRAINT subscription_plans_pkey PRIMARY KEY (id);


--
-- Name: team_members team_members_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.team_members
    ADD CONSTRAINT team_members_pkey PRIMARY KEY (id);


--
-- Name: teams teams_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.teams
    ADD CONSTRAINT teams_pkey PRIMARY KEY (id);


--
-- Name: todo_labels todo_labels_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.todo_labels
    ADD CONSTRAINT todo_labels_pkey PRIMARY KEY (todo_id, label_id);


--
-- Name: todos todos_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.todos
    ADD CONSTRAINT todos_pkey PRIMARY KEY (id);


--
-- Name: trial_usage trial_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.trial_usage
    ADD CONSTRAINT trial_usage_pkey PRIMARY KEY (email);


--
-- Name: user_subscriptions user_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.user_subscriptions
    ADD CONSTRAINT user_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: user_subscriptions user_subscriptions_user_id_key; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.user_subscriptions
    ADD CONSTRAINT user_subscriptions_user_id_key UNIQUE (user_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: idx_activities_user; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_activities_user ON public.activities USING btree (user_id);


--
-- Name: idx_filters_user_id; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_filters_user_id ON public.filters USING btree (user_id);


--
-- Name: idx_invitations_token; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_invitations_token ON public.invitations USING btree (invite_token);


--
-- Name: idx_team_members_team; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_team_members_team ON public.team_members USING btree (team_id);


--
-- Name: idx_team_members_user; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_team_members_user ON public.team_members USING btree (user_id);


--
-- Name: idx_todos_due_date; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_todos_due_date ON public.todos USING btree (due_date);


--
-- Name: idx_todos_label_id; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_todos_label_id ON public.todos USING btree (label_id);


--
-- Name: idx_todos_project_id; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_todos_project_id ON public.todos USING btree (project_id);


--
-- Name: idx_todos_team_id; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_todos_team_id ON public.todos USING btree (team_id);


--
-- Name: idx_todos_user_id; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_todos_user_id ON public.todos USING btree (user_id);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_users_email ON public.users USING btree (email);


--
-- Name: users set_timestamp; Type: TRIGGER; Schema: public; Owner: klarto_api_user
--

CREATE TRIGGER set_timestamp BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();


--
-- Name: filters fk_filters_user; Type: FK CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.filters
    ADD CONSTRAINT fk_filters_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: todos fk_todos_label; Type: FK CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.todos
    ADD CONSTRAINT fk_todos_label FOREIGN KEY (label_id) REFERENCES public.labels(id) ON DELETE SET NULL;


--
-- Name: todos fk_todos_team; Type: FK CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.todos
    ADD CONSTRAINT fk_todos_team FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE SET NULL;


--
-- Name: todos fk_todos_user; Type: FK CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.todos
    ADD CONSTRAINT fk_todos_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: todo_labels todo_labels_label_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.todo_labels
    ADD CONSTRAINT todo_labels_label_id_fkey FOREIGN KEY (label_id) REFERENCES public.labels(id) ON DELETE CASCADE;


--
-- Name: todo_labels todo_labels_todo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.todo_labels
    ADD CONSTRAINT todo_labels_todo_id_fkey FOREIGN KEY (todo_id) REFERENCES public.todos(id) ON DELETE CASCADE;


--
-- Name: user_subscriptions user_subscriptions_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.user_subscriptions
    ADD CONSTRAINT user_subscriptions_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.subscription_plans(id);


--
-- Name: user_subscriptions user_subscriptions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.user_subscriptions
    ADD CONSTRAINT user_subscriptions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- PostgreSQL database dump complete
--

\unrestrict JRGfM4cWFvMYZeloyhRh5wbmPeMeY5rVyJE45UNH0oMgqQLSQ6wu5FWJnaXPl9Z

